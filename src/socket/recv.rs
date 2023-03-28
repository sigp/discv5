//! This is a standalone task that handles UDP packets as they are received.
//!
//! Every UDP packet passes a filter before being processed.

use super::filter::{Filter, FilterConfig};
use crate::{metrics::METRICS, node_info::NodeAddress, packet::*, Executor};
use parking_lot::RwLock;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};

use tracing::{debug, trace, warn};

/// The object sent back by the Recv handler.
pub struct InboundPacket {
    /// The originating socket addr.
    pub src_address: SocketAddr,
    /// The packet header.
    pub header: PacketHeader,
    /// The message of the packet.
    pub message: Vec<u8>,
    /// The authenticated data of the packet.
    pub authenticated_data: Vec<u8>,
}

/// Convenience objects for setting up the recv handler.
pub struct RecvHandlerConfig {
    pub filter_config: FilterConfig,
    /// If the filter is enabled this sets the default timeout for bans enacted by the filter.
    pub ban_duration: Option<Duration>,
    pub executor: Box<dyn Executor>,
    pub recv: Arc<UdpSocket>,
    pub second_recv: Option<Arc<UdpSocket>>,
    pub local_node_id: enr::NodeId,
    pub expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
}

/// The main task that handles inbound UDP packets.
pub(crate) struct RecvHandler {
    /// The UDP recv socket.
    recv: Arc<UdpSocket>,
    /// An option second UDP socket. Used when dialing over both Ipv4 and Ipv6.
    second_recv: Option<Arc<UdpSocket>>,
    /// Simple hack to alternate reading from the first or the second socket.
    /// The list of waiting responses. These are used to allow incoming packets from sources
    /// that we are expected a response from bypassing the rate-limit filters.
    expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
    /// The packet filter which decides whether to accept or reject inbound packets.
    filter: Filter,
    /// The local node id used to decrypt headers of messages.
    node_id: enr::NodeId,
    /// The channel to send the packet handler.
    handler: mpsc::Sender<InboundPacket>,
    /// Exit channel to shutdown the recv handler.
    exit: oneshot::Receiver<()>,
}

impl RecvHandler {
    /// Spawns the `RecvHandler` on a provided executor.
    pub(crate) fn spawn(
        config: RecvHandlerConfig,
    ) -> (mpsc::Receiver<InboundPacket>, oneshot::Sender<()>) {
        let (exit_sender, exit) = oneshot::channel();
        let RecvHandlerConfig {
            filter_config,
            ban_duration,
            executor,
            recv,
            second_recv,
            local_node_id,
            expected_responses,
        } = config;

        let filter_enabled = filter_config.enabled;

        // create the channel to send decoded packets to the handler
        let (handler, handler_recv) = mpsc::channel(30);

        let mut recv_handler = RecvHandler {
            recv,
            second_recv,
            expected_responses,
            filter: Filter::new(filter_config, ban_duration),
            node_id: local_node_id,
            handler,
            exit,
        };

        // start the handler
        executor.spawn(Box::pin(async move {
            debug!("Recv handler starting");
            recv_handler.start(filter_enabled).await;
        }));
        (handler_recv, exit_sender)
    }

    /// The main future driving the recv handler. This will shutdown when the exit future is fired.
    async fn start(&mut self, filter_enabled: bool) {
        // Interval to prune to rate limiter.
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut first_buffer = [0; MAX_PACKET_SIZE];
        let mut second_buffer = [0; MAX_PACKET_SIZE];
        use futures::future::OptionFuture;
        // We want to completely deactivate this branch of the select when there is no second
        // socket to receive from.
        let check_second_recv = self.second_recv.is_some();

        loop {
            tokio::select! {
                Ok((length, src)) = self.recv.recv_from(&mut first_buffer) => {
                    METRICS.add_recv_bytes(length);
                    self.handle_inbound(src, length, &first_buffer).await;
                }
                Some(Ok((length, src))) = Into::<OptionFuture<_>>::into(self.second_recv.as_ref().map(|second_recv|second_recv.recv_from(&mut second_buffer))), if check_second_recv => {
                    METRICS.add_recv_bytes(length);
                    self.handle_inbound(src, length, &second_buffer).await;
                }
                _ = interval.tick(), if filter_enabled => {
                    self.filter.prune_limiter();
                },
                _ = &mut self.exit => {
                    debug!("Recv handler shutdown");
                    return;
                }
            }
        }
    }

    /// Handles in incoming packet. Passes through the filter, decodes and sends to the packet
    /// handler.
    async fn handle_inbound(
        &mut self,
        src_address: SocketAddr,
        length: usize,
        recv_buffer: &[u8; MAX_PACKET_SIZE],
    ) {
        // Permit all expected responses
        let permitted = self.expected_responses.read().get(&src_address).is_some();

        // Perform the first run of the filter. This checks for rate limits and black listed IP
        // addresses.
        if !permitted && !self.filter.initial_pass(&src_address) {
            trace!("Packet filtered from source: {:?}", src_address);
            return;
        }
        // Decodes the packet
        let (packet, authenticated_data) =
            match Packet::decode(&self.node_id, &recv_buffer[..length]) {
                Ok(p) => p,
                Err(e) => {
                    debug!("Packet decoding failed: {:?}", e); // could not decode the packet, drop it
                    return;
                }
            };

        // If this is not a challenge packet, we immediately know its src_id and so pass it
        // through the second filter.
        if let Some(node_id) = packet.src_id() {
            // Construct the node address
            let node_address = NodeAddress {
                socket_addr: src_address,
                node_id,
            };

            // Perform packet-level filtering
            if !permitted && !self.filter.final_pass(&node_address, &packet) {
                return;
            }
        }

        let inbound = InboundPacket {
            src_address,
            header: packet.header,
            message: packet.message,
            authenticated_data,
        };

        // send the filtered decoded packet to the handler.
        self.handler
            .send(inbound)
            .await
            .unwrap_or_else(|e| warn!("Could not send packet to handler: {}", e));
    }
}
