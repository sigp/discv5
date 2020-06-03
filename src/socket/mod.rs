use crate::packet::*;
use crate::Executor;
use recv::*;
use send::*;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

mod filter;
mod recv;
mod send;

pub use filter::FilterConfig;
pub use recv::{InboundPacket, MAX_PACKET_SIZE};
pub use send::OutboundPacket;

/// Convenience objects for setting up the recv handler.
pub struct SocketConfig<T: Executor> {
    /// The executor to spawn the tasks.
    pub executor: T,
    /// The listening socke.
    pub socket_addr: SocketAddr,
    /// Configuration details for the packet filter.
    pub filter_config: FilterConfig,
    /// The WhoAreYou magic packet.
    pub whoareyou_magic: [u8; MAGIC_LENGTH],
}

/// Creates the UDP socket and handles the exit futures for the send/recv UDP handlers.
pub struct Socket {
    send: mpsc::Sender<OutboundPacket>,
    recv: mpsc::Receiver<InboundPacket>,
    sender_exit: oneshot::Sender<()>,
    recv_exit: oneshot::Sender<()>,
}

impl Socket {
    /// Creates a UDP socket, spawns a send/recv task and returns the channels.
    /// If this struct is dropped, the send/recv tasks will shutdown.
    pub(crate) fn new(config: &SocketConfig) -> Self {
        // set up the UDP socket
        let socket = {
            #[cfg(unix)]
            fn platform_specific(s: &net2::UdpBuilder) -> std::io::Result<()> {
                net2::unix::UnixUdpBuilderExt::reuse_port(s, true)?;
                Ok(())
            }
            #[cfg(not(unix))]
            fn platform_specific(_: &net2::UdpBuilder) -> std::io::Result<()> {
                Ok(())
            }
            let builder = net2::UdpBuilder::new_v4()?;
            builder.reuse_address(true)?;
            platform_specific(&builder)?;
            builder.bind(config.socket_addr)?
        };
        let socket = tokio::net::UdpSocket::from_std(socket)?;

        // create the channel to receive decoded packets from the recv handler
        let (handler_send, handler_recv) = mpsc::channel(30);

        // split the UDP socket
        let (recv_udp, send_udp) = socket.split();

        // spawn the recv handler
        let recv_exit = RecvHandler::spawn(config, handler_send, recv_udp);
        // spawn the sender handler
        let (sender, sender_exit) = SendHandler::spawn(config, send_udp);

        return Socket {
            sender_exit,
            recv_exit,
        };
    }
}

impl<T> std::ops::Drop for Socket<T> {
    // close the send/recv handlers
    fn drop(&mut self) {
        let _ = self.sender_exit.send(());
        let _ = self.recv_exit.send(());
    }
}
