use crate::{node_info::NodeAddress, packet::MessageNonce, Discv5Error, Enr, IpMode};
use async_trait::async_trait;
use delay_map::HashSetDelay;
use enr::NodeId;
use futures::{Stream, StreamExt};
use rand::Rng;
use std::{
    collections::HashMap,
    fmt::Debug,
    net::{IpAddr, SocketAddr, UdpSocket},
    ops::RangeInclusive,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use thiserror::Error;

/// The expected shortest lifetime in most NAT configurations of a punched hole in seconds.
pub const DEFAULT_HOLE_PUNCH_LIFETIME: u64 = 20;
/// The default number of ports to try before concluding that the local node is behind NAT.
pub const DEFAULT_PORT_BIND_TRIES: usize = 4;
/// Port range that is not impossible to bind to.
pub const USER_AND_DYNAMIC_PORTS: RangeInclusive<u16> = 1025..=u16::MAX;

/// An error occurred whilst attempting to hole punch NAT.
#[derive(Debug, Error)]
pub enum Error {
    #[error("NAT error, failed as initiator of a hole punch attempt, {0}")]
    Initiator(Discv5Error),
    #[error("NAT error, failed as relay of a hole punch attempt, {0}")]
    Relay(Discv5Error),
    #[error("NAT error, failed as target of a hole punch attempt, {0}")]
    Target(Discv5Error),
}

#[async_trait]
pub trait NatHolePunch {
    /// A request times out. Should trigger the initiation of a hole punch attempt, given a
    /// transitive route to the target exists.
    async fn on_request_time_out(
        &mut self,
        relay: NodeAddress,
        local_enr: Enr, // initiator-enr
        timed_out_nonce: MessageNonce,
        target_session_index: NodeAddress,
    ) -> Result<(), Error>;
    /// A RelayInit notification is received over discv5 indicating this node is the relay. Should
    /// trigger sending a RelayMsg to the target.
    async fn on_relay_init(
        &mut self,
        initr: Enr,
        tgt: NodeId,
        timed_out_nonce: MessageNonce,
    ) -> Result<(), Error>;
    /// A RelayMsg notification is received over discv5 indicating this node is the target. Should
    /// trigger a WHOAREYOU to be sent to the initiator using the `nonce` in the RelayMsg.
    async fn on_relay_msg(
        &mut self,
        initr: Enr,
        timed_out_nonce: MessageNonce,
    ) -> Result<(), Error>;
    /// A punched hole closes. Should trigger an empty packet to be sent to the peer.
    async fn on_hole_punch_expired(&mut self, dst: SocketAddr) -> Result<(), Error>;
}

/// Types necessary implement trait [`NatHolePunch`] on [`super::Handler`].
pub(crate) struct NatHolePunchUtils {
    /// Ip mode as set in config.
    pub ip_mode: IpMode,
    /// This node has been observed to be behind a NAT.
    pub is_behind_nat: Option<bool>,
    /// The last peer to send us a new peer in a NODES response is stored as the new peer's
    /// potential relay until the first request to the new peer after its discovery is either
    /// responded or failed.
    pub new_peer_latest_relay: HashMap<NodeId, NodeAddress>,
    /// Keeps track if this node needs to send a packet to a peer in order to keep a hole punched
    /// for it in its NAT.
    pub hole_punch_tracker: HashSetDelay<SocketAddr>,
}

impl NatHolePunchUtils {
    pub(crate) fn new(listen_port: u16, local_enr: &Enr, ip_mode: IpMode) -> Self {
        let mut nat_hole_puncher = NatHolePunchUtils {
            ip_mode,
            is_behind_nat: None,
            new_peer_latest_relay: Default::default(),
            hole_punch_tracker: HashSetDelay::new(Duration::from_secs(DEFAULT_HOLE_PUNCH_LIFETIME)),
        };
        // Optimistically only test one advertised socket, ipv4 has precedence. If it is
        // reachable, assumption is made that also the other ip version socket is reachable.
        match (
            local_enr.ip4(),
            local_enr.udp4(),
            local_enr.ip6(),
            local_enr.udp6(),
        ) {
            (Some(ip), port, _, _) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, Some(ip.into()), port);
            }
            (_, _, Some(ip6), port) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, Some(ip6.into()), port);
            }
            (None, Some(port), _, _) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, None, Some(port));
            }
            (_, _, None, Some(port)) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, None, Some(port));
            }
            (None, None, None, None) => {}
        }
        nat_hole_puncher
    }

    pub(crate) fn track(&mut self, peer_socket: SocketAddr) {
        if self.is_behind_nat == Some(false) {
            return;
        }
        self.hole_punch_tracker.insert(peer_socket);
    }

    /// Called when a new observed address is reported at start up or after a
    /// [`crate::Discv5Event::SocketUpdated`].
    pub(crate) fn set_is_behind_nat(
        &mut self,
        listen_port: u16,
        observed_ip: Option<IpAddr>,
        observed_port: Option<u16>,
    ) {
        if Some(listen_port) != observed_port {
            self.is_behind_nat = Some(true);
            return;
        }
        // Without and observed IP it is too early to conclude if the local node is behind a NAT,
        // return.
        let Some(ip) = observed_ip else {
            return;
        };
        self.is_behind_nat = Some(is_behind_nat(ip, None, None));
    }
}

impl Stream for NatHolePunchUtils {
    type Item = Result<SocketAddr, String>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Until ip voting is done and an observed public address is finalised, all nodes act as
        // if they are behind a NAT.
        if self.is_behind_nat == Some(false) || self.hole_punch_tracker.is_empty() {
            return Poll::Pending;
        }
        self.hole_punch_tracker.poll_next_unpin(cx)
    }
}

/// Helper function to test if the local node is behind NAT based on the node's observed reachable
/// socket.
pub fn is_behind_nat(
    observed_ip: IpAddr,
    unused_port_range: Option<RangeInclusive<u16>>,
    max_retries: Option<usize>,
) -> bool {
    // If the node cannot bind to the observed address at any of some random ports, we
    // conclude it is behind NAT.
    let mut rng = rand::thread_rng();
    let unused_port_range = match unused_port_range {
        Some(range) => range,
        None => USER_AND_DYNAMIC_PORTS,
    };
    let retries = match max_retries {
        Some(max) => max,
        None => DEFAULT_PORT_BIND_TRIES,
    };
    for _ in 0..retries {
        let rnd_port: u16 = rng.gen_range(unused_port_range.clone());
        if UdpSocket::bind((observed_ip, rnd_port)).is_ok() {
            return false;
        }
    }
    true
}
