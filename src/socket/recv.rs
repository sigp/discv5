//! This is a standalone task that handles UDP packets as they are received.
//!
//! Every UDP packet passes a filter before being processed.

use super::filter::{Filter, FilterConfig};
use crate::node_info::NodeAddress;
use crate::packet::*;
use crate::Executor;
use log::{debug, trace};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

pub(crate) const MAX_PACKET_SIZE: usize = 1280;

/// The object sent back by the Recv handler.
pub struct InboundPacket {
    /// The originating socket addr.
    pub node_address: NodeAddress,
    /// The packet header.
    pub header: PacketHeader,
    /// The message of the packet.
    pub message: Vec<u8>,
    /// The authenticated data if required (packets that are non-challenge) packets.
    pub authenticated_data: Vec<u8>,
}

/// Convenience objects for setting up the recv handler.
pub struct RecvHandlerConfig {
    pub filter_config: FilterConfig,
    pub max_findnode_distances: usize,
    pub executor: Box<dyn Executor>,
    pub recv: tokio::net::udp::RecvHalf,
    pub local_key: [u8; 16],
    pub expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
}

/// The main task that handles inbound UDP packets.
pub(crate) struct RecvHandler {
    /// The UDP recv socket.
    recv: tokio::net::udp::RecvHalf,
    /// The list of waiting responses. These are used to allow incoming packets from sources
    /// that we are expected a response from bypassing the rate-limit filters.
    expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
    /// The packet filter which decides whether to accept or reject inbound packets.
    filter: Filter,
    /// The buffer to accept inbound datagrams.
    recv_buffer: [u8; MAX_PACKET_SIZE],
    /// The local key used to decrypt headers of messages. This is the first 16 bytes of our local
    /// node id.
    local_key: [u8; 16],
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

        // create the channel to send decoded packets to the handler
        let (handler, handler_recv) = mpsc::channel(30);

        let mut recv_handler = RecvHandler {
            recv: config.recv,
            filter: Filter::new(&config.filter_config),
            recv_buffer: [0; MAX_PACKET_SIZE],
            local_key: config.local_key,
            expected_responses: config.expected_responses,
            handler,
            exit,
        };

        // start the handler
        config.executor.spawn(Box::pin(async move {
            debug!("Recv handler starting");
            recv_handler.start().await;
        }));
        (handler_recv, exit_sender)
    }

    /// The main future driving the recv handler. This will shutdown when the exit future is fired.
    async fn start(&mut self) {
        loop {
            tokio::select! {
                Ok((length, src)) = self.recv.recv_from(&mut self.recv_buffer) => {
                    self.handle_inbound(src, length).await;
                }
                _ = &mut self.exit => {
                    debug!("Recv handler shutdown");
                    return;
                }
            }
        }
    }

    /// Handles in incoming packet. Passes through the filter, decodes and sends to the packet
    /// handler.
    async fn handle_inbound(&mut self, src: SocketAddr, length: usize) {
        // Permit all expected responses
        let permitted = self.expected_responses.read().get(&src).is_some();

        // Perform the first run of the filter. This checks for rate limits and black listed IP
        // addresses.
        if !permitted && !self.filter.initial_pass(&src) {
            trace!("Packet filtered from source: {:?}", src);
            return;
        }
        // Decodes the packet
        let packet = match Packet::decode(&self.local_key, &self.recv_buffer[..length]) {
            Ok(p) => p,
            Err(e) => {
                debug!("Packet decoding failed: {:?}", e); // could not decode the packet, drop it
                return;
            }
        };

        // Perform packet-level filtering
        if !permitted && !self.filter.final_pass(&src, &packet) {
            return;
        }

        // Construct the node address
        let node_address = NodeAddress {
            socket_addr: src,
            node_id: packet.header.src_id,
        };

        // obtain any packet authenticated data
        let authenticated_data = packet.header.authenticated_data();

        let inbound = InboundPacket {
            node_address,
            header: packet.header,
            message: packet.message,
            authenticated_data,
        };

        // send the filtered decoded packet to the handler.
        self.handler.send(inbound).await.unwrap_or_else(|_| ());
    }
}
