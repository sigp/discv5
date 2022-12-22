use crate::{Executor, IpMode};
use parking_lot::RwLock;
use recv::*;
use send::*;
use socket2::{Domain, Protocol, Socket as Socket2, Type};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    net::SocketAddr,
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

/// Convenience objects for setting up the recv handler.
pub struct SocketConfig {
    /// The executor to spawn the tasks.
    pub executor: Box<dyn Executor + Send + Sync>,
    /// The listening socket.
    pub socket_addr: SocketAddr,
    /// Configuration details for the packet filter.
    pub filter_config: FilterConfig,
    /// Type of socket to create.
    pub ip_mode: IpMode,
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
    async fn new_socket(
        socket_addr: &SocketAddr,
        ip_mode: IpMode,
    ) -> Result<tokio::net::UdpSocket, Error> {
        match ip_mode {
            IpMode::Ip4 => match socket_addr {
                SocketAddr::V6(_) => Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Cannot create an ipv4 socket from an ipv6 address",
                )),
                ip4 => tokio::net::UdpSocket::bind(ip4).await,
            },
            IpMode::Ip6 {
                enable_mapped_addresses,
            } => {
                let addr = match socket_addr {
                    SocketAddr::V4(_) => Err(Error::new(
                        ErrorKind::InvalidInput,
                        "Cannot create an ipv6 socket from an ipv4 address",
                    )),
                    SocketAddr::V6(ip6) => Ok((*ip6).into()),
                }?;
                let socket = Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
                let only_v6 = !enable_mapped_addresses;
                socket.set_only_v6(only_v6)?;
                socket.set_nonblocking(true)?;
                socket.bind(&addr)?;
                tokio::net::UdpSocket::from_std(socket.into())
            }
        }
    }

    /// Creates a UDP socket, spawns a send/recv task and returns the channels.
    /// If this struct is dropped, the send/recv tasks will shutdown.
    /// This needs to be run inside of a tokio executor.
    pub(crate) async fn new(config: SocketConfig) -> Result<Self, Error> {
        let socket = Socket::new_socket(&config.socket_addr, config.ip_mode).await?;

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
