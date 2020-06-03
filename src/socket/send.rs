//! This is a standalone task that encodes and sends Discv5 UDP packets
use crate::packet::*;
use crate::Executor;
use log::debug;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

pub struct OutboundPacket {
    /// The originating socket addr.
    dst: SocketAddr,
    /// The packet to be encoded.
    packet: Packet,
}

/// The main task that handles inbound UDP packets.
pub(crate) struct SendHandler {
    /// The UDP send socket.
    send: tokio::net::udp::SendHalf,
    /// The channel to respond to send requests.
    handler_recv: mpsc::Receiver<OutboundPacket>,
    /// Exit channel to shutdown the handler.
    exit: oneshot::Receiver<()>,
}

impl SendHandler {
    /// Spawns the `SendHandler` on a provided executor.
    /// This returns the sending channel to process `OutboundPacket`'s and an exit channel to
    /// shutdown the handler.
    pub(crate) fn spawn<T: Executor>(
        executor: T,
        send: tokio::net::udp::SendHalf,
    ) -> (mpsc::Sender<OutboundPacket>, oneshot::Sender<()>) {
        let (exit_send, exit) = oneshot::channel();
        let (handler_send, handler_recv) = mpsc::channel(30);

        let mut send_handler = SendHandler {
            send,
            handler_recv,
            exit,
        };

        // start the handler
        executor.spawn(Box::pin(async move {
            debug!("Send handler starting");
            send_handler.start().await;
        }));
        (handler_send, exit_send)
    }

    /// The main future driving the send handler. This will shutdown when the exit future is fired.
    async fn start(&mut self) {
        loop {
            tokio::select! {
                Some(packet) = self.handler_recv.recv() => {
                    self.send.send_to(&packet.packet.encode(), &packet.dst).await;
                }
                _ = &mut self.exit => {
                    debug!("Send handler shutdown");
                    break;
                }
            }
        }
    }
}
