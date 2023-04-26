use crate::{node_info::NodeAddress, Enr, IpMode};
use delay_map::HashSetDelay;
use enr::NodeId;
use futures::{Stream, StreamExt};
use nat_hole_punch::DEFAULT_HOLE_PUNCH_LIFETIME;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Types necessary implement trait [`nat_hole_punch::NatHolePunch`] on
/// [`crate::handler::Handler`].
pub(crate) struct NatHolePuncher {
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

impl NatHolePuncher {
    pub(crate) fn new(listen_port: u16, local_enr: &Enr, ip_mode: IpMode) -> Self {
        let mut nat_hole_puncher = NatHolePuncher {
            ip_mode,
            is_behind_nat: None,
            new_peer_latest_relay: Default::default(),
            hole_punch_tracker: HashSetDelay::new(Duration::from_secs(DEFAULT_HOLE_PUNCH_LIFETIME)),
        };
        // Optimistically only test one advertised socket, ipv4 has precedence.
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

    // Called when a new observed address is reported at start up or after a
    // `Discv5Event::SocketUpdated(socket)`
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
        self.is_behind_nat = Some(nat_hole_punch::is_behind_nat(ip, None, None));
    }
}

impl Stream for NatHolePuncher {
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
