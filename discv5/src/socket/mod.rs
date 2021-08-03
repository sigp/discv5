use crate::Executor;
use parking_lot::RwLock;
use recv::*;
use send::*;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

mod filter;
mod recv;
mod send;

pub use filter::{
    rate_limiter::{RateLimiter, RateLimiterBuilder},
    FilterConfig,
};
pub use recv::InboundPacket;
pub use send::OutboundPacket;
/// Convenience objects for setting up the recv handler.
pub struct SocketConfig {
    /// The executor to spawn the tasks.
    pub executor: Box<dyn Executor + Send + Sync>,
    /// The listening socket.
    pub socket_addr: SocketAddr,
    /// Configuration details for the packet filter.
    pub filter_config: FilterConfig,
    /// If the filter is enabled this sets the default timeout for bans enacted by the filter.
    pub ban_duration: Option<Duration>,
    /// The expected responses reference.
    pub expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
    /// The local node id used to decrypt messages.
    pub local_node_id: enr::NodeId,
}

/// Creates the UDP socket and handles the exit futures for the send/recv UDP handlers.
pub struct Socket {
    pub send: mpsc::Sender<OutboundPacket>,
    pub recv: mpsc::Receiver<InboundPacket>,
    sender_exit: Option<oneshot::Sender<()>>,
    recv_exit: Option<oneshot::Sender<()>>,
}

impl Socket {
    /// This creates and binds a new UDP socket.
    // In general this function can be expanded to handle more advanced socket creation.
    pub(crate) async fn new_socket(
        socket: &SocketAddr,
    ) -> Result<tokio::net::UdpSocket, std::io::Error> {
        tokio::net::UdpSocket::bind(socket).await
    }

    /// Creates a UDP socket, spawns a send/recv task and returns the channels.
    /// If this struct is dropped, the send/recv tasks will shutdown.
    /// This needs to be run inside of a tokio executor.
    pub(crate) fn new(
        socket: tokio::net::UdpSocket,
        config: SocketConfig,
    ) -> Result<Self, std::io::Error> {
        // Arc the udp socket for the send/recv tasks.
        let recv_udp = Arc::new(socket);
        let send_udp = recv_udp.clone();

        // spawn the recv handler
        let recv_config = RecvHandlerConfig {
            filter_config: config.filter_config,
            executor: config.executor.clone(),
            recv: recv_udp,
            local_node_id: config.local_node_id,
            expected_responses: config.expected_responses,
            ban_duration: config.ban_duration,
        };

        let (recv, recv_exit) = RecvHandler::spawn(recv_config);
        // spawn the sender handler
        let (send, sender_exit) = SendHandler::spawn(config.executor.clone(), send_udp);

        Ok(Socket {
            send,
            recv,
            sender_exit: Some(sender_exit),
            recv_exit: Some(recv_exit),
        })
    }
}

impl std::ops::Drop for Socket {
    // close the send/recv handlers
    fn drop(&mut self) {
        let _ = self
            .sender_exit
            .take()
            .expect("Exit always exists")
            .send(());
        let _ = self.recv_exit.take().expect("Exit always exists").send(());
    }
}
