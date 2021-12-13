//! This is a standalone task that encodes and sends Discv5 UDP packets
use crate::{metrics::METRICS, node_info::NodeAddress, packet::*, Executor};
use std::sync::Arc;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use tracing::{debug, trace, warn};

pub struct OutboundPacket {
    /// The destination node address
    pub node_address: NodeAddress,
    /// The packet to be encoded.
    pub packet: Packet,
}

/// The main task that handles outbound UDP packets.
pub(crate) struct SendHandler {
    /// The UDP send socket.
    send: Arc<UdpSocket>,
    /// The channel to respond to send requests.
    handler_recv: mpsc::Receiver<OutboundPacket>,
    /// Exit channel to shutdown the handler.
    exit: oneshot::Receiver<()>,
}

impl SendHandler {
    /// Spawns the `SendHandler` on a provided executor.
    /// This returns the sending channel to process `OutboundPacket`'s and an exit channel to
    /// shutdown the handler.
    pub(crate) fn spawn(
        executor: Box<dyn Executor>,
        send: Arc<UdpSocket>,
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
                    let encoded_packet = packet.packet.encode(&packet.node_address.node_id);
                    if encoded_packet.len() > MAX_PACKET_SIZE {
                        warn!("Sending packet larger than max size: {} max: {}", encoded_packet.len(), MAX_PACKET_SIZE);
                    }
                    if let Err(e) = self.send.send_to(&encoded_packet, &packet.node_address.socket_addr).await {
                        trace!("Could not send packet. Error: {:?}", e);
                    } else {
                        METRICS.add_sent_bytes(encoded_packet.len());
                    }
                }
                _ = &mut self.exit => {
                    debug!("Send handler shutdown");
                    return;
                }
            }
        }
    }
}
