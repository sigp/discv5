use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    ops::RangeInclusive,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use derive_more::{Deref, DerefMut};
use enr::NodeId;
use futures::{channel::mpsc, Stream, StreamExt};
use lru::LruCache;
use rand::Rng;

use crate::{lru_time_cache::LruTimeCache, node_info::NodeAddress, Enr, IpMode};

/// The expected shortest lifetime in most NAT configurations of a punched hole in seconds.
pub const DEFAULT_HOLE_PUNCH_LIFETIME: u64 = 20;
/// The default number of ports to try before concluding that the local node is behind NAT.
pub const PORT_BIND_TRIES: usize = 4;
/// Port range that is not impossible to bind to.
pub const USER_AND_DYNAMIC_PORTS: RangeInclusive<u16> = 1025..=u16::MAX;

/// Aggregates types necessary to implement nat hole punching for [`crate::handler::Handler`].
pub struct NatHolePunchUtils {
    /// Ip mode as set in config.
    pub ip_mode: IpMode,
    /// This node has been observed to be behind a NAT.
    pub is_behind_nat: Option<bool>,
    /// The last peer to send us a new peer in a NODES response is stored as the new peer's
    /// potential relay until the first request to the new peer after its discovery is either
    /// responded or failed. The cache will usually be emptied by successful or failed session
    /// establishment, but for the edge case that a NODES response is returned for an ended query
    /// and hence an attempt to establish a session with those nodes isn't initiated, a bound on
    /// the relay cache is set equivalent to the Handler's `session_cache_capacity`.
    pub new_peer_latest_relay_cache: LruCache<NodeId, NodeAddress>,
    /// Keeps track if this node needs to send a packet to a peer in order to keep a hole punched
    /// for it in its NAT.
    hole_punch_tracker: NatHolePunchTracker,
    /// Ports to trie to bind to check if this node is behind NAT.
    pub unused_port_range: Option<RangeInclusive<u16>>,
    /// If the filter is enabled this sets the default timeout for bans enacted by the filter.
    pub ban_duration: Option<Duration>,
}

impl NatHolePunchUtils {
    pub fn new(
        listen_port: u16,
        local_enr: &Enr,
        ip_mode: IpMode,
        unused_port_range: Option<RangeInclusive<u16>>,
        ban_duration: Option<Duration>,
        session_cache_capacity: usize,
    ) -> Self {
        let mut nat_hole_puncher = NatHolePunchUtils {
            ip_mode,
            is_behind_nat: None,
            new_peer_latest_relay_cache: LruCache::new(session_cache_capacity),
            hole_punch_tracker: NatHolePunchTracker::new(session_cache_capacity),
            unused_port_range,
            ban_duration,
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
            (None, Some(port), _, _) | (_, _, None, Some(port)) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, None, Some(port));
            }
            (None, None, None, None) => {}
        }
        nat_hole_puncher
    }

    pub fn track(&mut self, peer_socket: SocketAddr) {
        if self.is_behind_nat == Some(false) {
            return;
        }
        self.hole_punch_tracker.insert(peer_socket, ());
    }

    pub fn untrack(&mut self, peer_socket: &SocketAddr) {
        _ = self.hole_punch_tracker.remove(peer_socket)
    }

    /// Called when a new observed address is reported at start up or after a
    /// [`crate::Discv5Event::SocketUpdated`].
    pub fn set_is_behind_nat(
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

        self.is_behind_nat = Some(match is_behind_nat(ip, &self.unused_port_range) {
            true => true,
            false => {
                // node assume it is behind NAT until now
                self.hole_punch_tracker.clear();
                false
            }
        });
    }
}

impl Stream for NatHolePunchUtils {
    type Item = SocketAddr;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Until ip voting is done and an observed public address is finalised, all nodes act as
        // if they are behind a NAT.
        if self.is_behind_nat == Some(false) || self.hole_punch_tracker.len() == 0 {
            return Poll::Pending;
        }
        self.hole_punch_tracker.expired_entries.poll_next_unpin(cx)
    }
}

#[derive(Deref, DerefMut)]
struct NatHolePunchTracker {
    #[deref]
    #[deref_mut]
    cache: LruTimeCache<SocketAddr, ()>,
    expired_entries: mpsc::Receiver<SocketAddr>,
}

impl NatHolePunchTracker {
    fn new(session_cache_capacity: usize) -> Self {
        let (tx, rx) = futures::channel::mpsc::channel::<SocketAddr>(session_cache_capacity);
        Self {
            cache: LruTimeCache::new_with_expiry_feedback(
                Duration::from_secs(DEFAULT_HOLE_PUNCH_LIFETIME),
                Some(session_cache_capacity),
                tx,
            ),
            expired_entries: rx,
        }
    }
}

/// Helper function to test if the local node is behind NAT based on the node's observed reachable
/// socket.
fn is_behind_nat(observed_ip: IpAddr, unused_port_range: &Option<RangeInclusive<u16>>) -> bool {
    // If the node cannot bind to the observed address at any of some random ports, we
    // conclude it is behind NAT.
    let mut rng = rand::thread_rng();
    let unused_port_range = match unused_port_range {
        Some(range) => range,
        None => &USER_AND_DYNAMIC_PORTS,
    };
    for _ in 0..PORT_BIND_TRIES {
        let rnd_port: u16 = rng.gen_range(unused_port_range.clone());
        if UdpSocket::bind((observed_ip, rnd_port)).is_ok() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_not_behind_nat() {
        assert!(!is_behind_nat(IpAddr::from([127, 0, 0, 1]), &None));
    }

    #[test]
    fn test_is_behind_nat() {
        assert!(is_behind_nat(IpAddr::from([8, 8, 8, 8]), &None));
    }

    // ipv6 tests don't run in github ci https://github.com/actions/runner-images/issues/668
    #[test]
    fn test_is_not_behind_nat_ipv6() {
        assert!(!is_behind_nat(
            IpAddr::from([0u16, 0u16, 0u16, 0u16, 0u16, 0u16, 0u16, 1u16]),
            &None,
        ));
    }

    // ipv6 tests don't run in github ci https://github.com/actions/runner-images/issues/668
    #[test]
    fn test_is_behind_nat_ipv6() {
        // google's ipv6
        assert!(is_behind_nat(
            IpAddr::from([2001, 4860, 4860, 0u16, 0u16, 0u16, 0u16, 0u16]),
            &None,
        ));
    }
}
