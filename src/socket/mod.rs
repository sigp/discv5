use crate::Executor;
use parking_lot::RwLock;
use recv::*;
use send::*;
use socket2::{Domain, Protocol, Socket as Socket2, Type};
use std::{
    collections::HashMap,
    io::Error,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
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

/// Configuration for the sockets to listen on.
#[derive(Clone)]
pub enum ListenConfig {
    Ipv4 {
        ip: Ipv4Addr,
        port: u16,
    },
    Ipv6 {
        ip: Ipv6Addr,
        port: u16,
    },
    DualStack {
        ipv4: Ipv4Addr,
        ipv4_port: u16,
        ipv6: Ipv6Addr,
        ipv6_port: u16,
    },
}

/// Convenience objects for setting up the recv handler.
pub struct SocketConfig {
    /// The executor to spawn the tasks.
    pub executor: Box<dyn Executor + Send + Sync>,
    /// Configuration details for the packet filter.
    pub filter_config: FilterConfig,
    /// Type of socket to create.
    pub listen_config: ListenConfig,
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
    async fn new_socket(socket_addr: &SocketAddr) -> Result<tokio::net::UdpSocket, Error> {
        match socket_addr {
            SocketAddr::V4(ip4) => tokio::net::UdpSocket::bind(ip4).await,
            SocketAddr::V6(ip6) => {
                let socket = Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
                socket.set_only_v6(true)?;
                socket.set_nonblocking(true)?;
                socket.bind(&SocketAddr::V6(*ip6).into())?;
                tokio::net::UdpSocket::from_std(socket.into())
            }
        }
    }

    /// Creates a UDP socket, spawns a send/recv task and returns the channels.
    /// If this struct is dropped, the send/recv tasks will shutdown.
    /// This needs to be run inside of a tokio executor.
    pub(crate) async fn new(config: SocketConfig) -> Result<Self, Error> {
        let SocketConfig {
            executor,
            filter_config,
            listen_config,
            ban_duration,
            expected_responses,
            local_node_id,
        } = config;

        // For now intentionally forgettig which socket is the ipv4 and which is the ipv6 one.
        let (first_addr, maybe_second_addr): (SocketAddr, Option<_>) = match listen_config {
            ListenConfig::Ipv4 { ip, port } => ((ip, port).into(), None),
            ListenConfig::Ipv6 { ip, port } => ((ip, port).into(), None),
            ListenConfig::DualStack {
                ipv4,
                ipv4_port,
                ipv6,
                ipv6_port,
            } => ((ipv4, ipv4_port).into(), Some((ipv6, ipv6_port))),
        };
        let first_socket = Socket::new_socket(&first_addr).await?;
        let maybe_second_socket = match maybe_second_addr {
            Some(second_addr) => Some(Socket::new_socket(&second_addr.into()).await?),
            None => None,
        };

        // Arc the udp socket for the send/recv tasks.
        let recv_udp = Arc::new(first_socket);
        let send_udp = recv_udp.clone();

        let second_recv = maybe_second_socket.map(Arc::new);
        let second_send = second_recv.clone();

        // spawn the recv handler
        let recv_config = RecvHandlerConfig {
            filter_config,
            executor: executor.clone(),
            recv: recv_udp,
            second_recv,
            local_node_id,
            expected_responses,
            ban_duration,
        };

        let (recv, recv_exit) = RecvHandler::spawn(recv_config);
        // spawn the sender handler
        let (send, sender_exit) = SendHandler::spawn(executor, send_udp, second_send);

        Ok(Socket {
            send,
            recv,
            sender_exit: Some(sender_exit),
            recv_exit: Some(recv_exit),
        })
    }
}

impl Drop for Socket {
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
