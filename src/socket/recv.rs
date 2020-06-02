//! This is a standalone task that handles UDP packets as they are received.
//!
//! Every UDP packet passes a filter before being processed.

use super::filter::Filter;
pub use super::filter::FilterConfig;
use crate::packet::*;
use crate::Executor;
use log::debug;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

pub(crate) const MAX_PACKET_SIZE: usize = 1280;

/// The object sent back by the Recv handler.
pub struct InboundPacket {
    /// The originating socket addr.
    src: SocketAddr,
    /// The decoded packet.
    packet: Packet,
}

/// Convenience objects for setting up the recv handler.
pub struct RecvHandlerConfig<T: Executor> {
    pub filter_config: FilterConfig,
    pub executor: T,
    pub recv: tokio::net::udp::RecvHalf,
    pub whoareyou_magic: [u8; MAGIC_LENGTH],
    pub handler: mpsc::Sender<InboundPacket>,
}

/// The main task that handles inbound UDP packets.
pub(crate) struct RecvHandler {
    /// The UDP recv socket.
    recv: tokio::net::udp::RecvHalf,
    /// The packet filter which decides whether to accept or reject inbound packets.
    filter: Filter,
    /// The buffer to accept inbound datagrams.
    recv_buffer: [u8; MAX_PACKET_SIZE],
    /// WhoAreYou Magic Value. Used to decode raw WHOAREYOU packets.
    whoareyou_magic: [u8; MAGIC_LENGTH],
    /// The channel to send the packet handler.
    handler: mpsc::Sender<InboundPacket>,
    /// Exit channel to shutdown the recv handler.
    exit: oneshot::Receiver<()>,
}

impl RecvHandler {
    /// Spawns the `RecvHandler` on a provided executor.
    pub(crate) fn spawn<T: Executor>(config: RecvHandlerConfig) -> oneshot::Sender {
        let (exit_sender, exit) = oneshot::channel();

        let mut recv_handler = RecvHandler {
            recv: config.recv,
            filter: Filter::new(config.filter_config),
            recv_buffer: [0; MAX_PACKET_SIZE],
            whoareyou_magic: config.whoareyou_magic,
            handler: config.handler,
            exit,
        };

        // start the handler
        config.executor.spawn(async move {
            debug!("Recv handler starting");
            recv_handler.start().await;
        });
        exit_sender
    }

    /// The main future driving the recv handler. This will shutdown when the exit future is fired.
    async fn start(&mut self) {
        loop {
            tokio::select! {
                (length, src) = self.recv.recv_from(&mut self.recv_buffer) => {
                    self.handle_inbound(src, length)
                }
                _ = self.exit => {
                    debug!("Recv handler shutdown");
                    break;
                }
            }
        }
    }

    /// Handles in incoming packet. Passes through the filter, decodes and sends to the packet
    /// handler.
    async fn handle_inbound(&mut self, src: SocketAddr, length: usize) {
        // Perform the first run of the filter. This checks for rate limits and black listed IP
        // addresses.
        if !self.filter.initial_pass(src: &SocketAddr) {
            return;
        }

        // Decodes the packet
        let packet = match Packet::decode(&self.recv_buffer[..length], &self.whoareyou_magic) {
            Ok(p) => p,
            Err(e) => {
                debug!("Packet decoding failed: {}", e); // could not decode the packet, drop it
                return;
            }
        };

        // Perform packet-level filtering
        if !self.filter.final_pass(src: &SocketAddr, packet: &Packet) {
            return;
        }

        let inbound = InboundPacket { src, packet };

        // send the filtered decoded packet to the handler.
        self.handler.send(inbound).await;
    }
}
