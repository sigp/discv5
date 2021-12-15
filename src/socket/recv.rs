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
    pub local_node_id: enr::NodeId,
    pub expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
}

/// The main task that handles inbound UDP packets.
pub(crate) struct RecvHandler {
    /// The UDP recv socket.
    recv: Arc<UdpSocket>,
    /// The list of waiting responses. These are used to allow incoming packets from sources
    /// that we are expected a response from bypassing the rate-limit filters.
    expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
    /// The packet filter which decides whether to accept or reject inbound packets.
    filter: Filter,
    /// The buffer to accept inbound datagrams.
    recv_buffer: [u8; MAX_PACKET_SIZE],
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

        let filter_enabled = config.filter_config.enabled;

        // create the channel to send decoded packets to the handler
        let (handler, handler_recv) = mpsc::channel(30);

        let mut recv_handler = RecvHandler {
            recv: config.recv,
            filter: Filter::new(config.filter_config, config.ban_duration),
            recv_buffer: [0; MAX_PACKET_SIZE],
            node_id: config.local_node_id,
            expected_responses: config.expected_responses,
            handler,
            exit,
        };

        // start the handler
        config.executor.spawn(Box::pin(async move {
            debug!("Recv handler starting");
            recv_handler.start(filter_enabled).await;
        }));
        (handler_recv, exit_sender)
    }

    /// The main future driving the recv handler. This will shutdown when the exit future is fired.
    async fn start(&mut self, filter_enabled: bool) {
        // Interval to prune to rate limiter.
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            tokio::select! {
                Ok((length, src)) = self.recv.recv_from(&mut self.recv_buffer) => {
                    METRICS.add_recv_bytes(length);
                    self.handle_inbound(src, length).await;
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
    async fn handle_inbound(&mut self, src_address: SocketAddr, length: usize) {
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
            match Packet::decode(&self.node_id, &self.recv_buffer[..length]) {
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
