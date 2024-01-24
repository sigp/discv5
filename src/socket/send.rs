//! This is a standalone task that encodes and sends Discv5 UDP packets
use crate::{metrics::METRICS, node_info::NodeAddress, packet::*, Executor};
use derive_more::From;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use tracing::{debug, error, trace, warn};

#[derive(From)]
pub enum Outbound {
    Packet(OutboundPacket),
    KeepHolePunched(SocketAddr),
}

impl Outbound {
    pub fn dst(&self) -> &SocketAddr {
        match self {
            Self::Packet(packet) => &packet.node_address.socket_addr,
            Self::KeepHolePunched(dst) => dst,
        }
    }
}

pub struct OutboundPacket {
    /// The destination node address
    pub node_address: NodeAddress,
    /// The packet to be encoded.
    pub packet: Packet,
}

/// The main task that handles outbound UDP packets.
pub(crate) struct SendHandler {
    /// The UDP send socket for IPv4.
    send_ipv4: Option<Arc<UdpSocket>>,
    /// The UDP send socket for IPv6.
    send_ipv6: Option<Arc<UdpSocket>>,
    /// The channel to respond to send requests.
    handler_recv: mpsc::Receiver<Outbound>,
    /// Exit channel to shutdown the handler.
    exit: oneshot::Receiver<()>,
}

enum Error {
    Io(std::io::Error),
    SocketMismatch,
}

impl SendHandler {
    /// Spawns the `SendHandler` on a provided executor.
    /// This returns the sending channel to process `OutboundPacket`'s and an exit channel to
    /// shutdown the handler.
    pub(crate) fn spawn<P: ProtocolIdentity>(
        executor: Box<dyn Executor>,
        send_ipv4: Option<Arc<UdpSocket>>,
        send_ipv6: Option<Arc<UdpSocket>>,
    ) -> (mpsc::Sender<Outbound>, oneshot::Sender<()>) {
        let (exit_send, exit) = oneshot::channel();
        let (handler_send, handler_recv) = mpsc::channel(30);

        let mut send_handler = SendHandler {
            send_ipv4,
            send_ipv6,
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
                    let (addr, encoded_packet) = match outbound {
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
                    if let Err(e) = self.send(&encoded_packet, &addr).await {
                        match e {
                            Error::Io(e) => {
                                trace!("Could not send packet to {addr} . Error: {e}");
                            },
                            Error::SocketMismatch => {
                                error!("Socket mismatch attempting to send a packet to {addr}.")
                            }
                        }
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

    async fn send(&self, encoded_packet: &[u8], socket_addr: &SocketAddr) -> Result<usize, Error> {
        let socket = match socket_addr {
            SocketAddr::V4(_) => {
                if let Some(socket) = self.send_ipv4.as_ref() {
                    socket
                } else {
                    return Err(Error::SocketMismatch);
                }
            }
            SocketAddr::V6(_) => {
                if let Some(socket) = self.send_ipv6.as_ref() {
                    socket
                } else {
                    return Err(Error::SocketMismatch);
                }
            }
        };

        socket
            .send_to(encoded_packet, socket_addr)
            .await
            .map_err(Error::Io)
    }
}
