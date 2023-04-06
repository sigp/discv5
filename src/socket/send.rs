//! This is a standalone task that encodes and sends Discv5 UDP packets
use crate::{metrics::METRICS, node_info::NodeAddress, packet::*, Executor};
use nat_hole_punch::impl_from_variant_wrap;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use tracing::{debug, trace, warn};

pub enum Outbound {
    Packet(OutboundPacket),
    KeepHolePunched(SocketAddr),
}

impl_from_variant_wrap!(, OutboundPacket, Outbound, Self::Packet);

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
    handler_recv: mpsc::Receiver<Outbound>,
    /// Exit channel to shutdown the handler.
    exit: oneshot::Receiver<()>,
}

impl SendHandler {
    /// Spawns the `SendHandler` on a provided executor.
    /// This returns the sending channel to process `OutboundPacket`'s and an exit channel to
    /// shutdown the handler.
    pub(crate) fn spawn<P: ProtocolIdentity>(
        executor: Box<dyn Executor>,
        send: Arc<UdpSocket>,
    ) -> (mpsc::Sender<Outbound>, oneshot::Sender<()>) {
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
            send_handler.start::<P>().await;
        }));
        (handler_send, exit_send)
    }

    /// The main future driving the send handler. This will shutdown when the exit future is fired.
    async fn start<P: ProtocolIdentity>(&mut self) {
        loop {
            tokio::select! {
                Some(outbound) = self.handler_recv.recv() => {
                    let (dst_addr, encoded_pkt) = match outbound {
                        Outbound::Packet(outbound_packet) => {
                            let dst_id = outbound_packet.node_address.node_id;
                            let encoded_packet = outbound_packet.packet.encode::<P>(&dst_id);
                            if encoded_packet.len() > MAX_PACKET_SIZE {
                                warn!("Sending packet larger than max size: {} max: {}", encoded_packet.len(), MAX_PACKET_SIZE);
                            }
                            let dst_addr = outbound_packet.node_address.socket_addr;
                            (dst_addr, encoded_packet)
                        }
                        Outbound::KeepHolePunched(dst) => (dst, vec![]),
                    };
                    if let Err(e) = self.send.send_to(&encoded_pkt, &dst_addr).await {
                        trace!("Could not send packet. Error: {:?}", e);
                    } else {
                        METRICS.add_sent_bytes(encoded_pkt.len());
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
