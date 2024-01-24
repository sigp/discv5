use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    ops::RangeInclusive,
    time::Duration,
};

use delay_map::HashSetDelay;
use enr::NodeId;
use lru::LruCache;
use rand::Rng;

use crate::{node_info::NodeAddress, Enr, IpMode};

/// The expected shortest lifetime in most NAT configurations of a punched hole in seconds.
pub const DEFAULT_HOLE_PUNCH_LIFETIME: u64 = 20;
/// The default number of ports to try before concluding that the local node is behind NAT.
pub const PORT_BIND_TRIES: usize = 4;
/// Port range that is not impossible to bind to.
pub const USER_AND_DYNAMIC_PORTS: RangeInclusive<u16> = 1025..=u16::MAX;

/// Aggregates types necessary to implement nat hole punching for [`crate::handler::Handler`].
pub struct Nat {
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
    pub hole_punch_tracker: HashSetDelay<SocketAddr>,
    /// Ports to trie to bind to check if this node is behind NAT.
    pub unused_port_range: Option<RangeInclusive<u16>>,
    /// If the filter is enabled this sets the default timeout for bans enacted by the filter.
    pub ban_duration: Option<Duration>,
    /// The number of unreachable ENRs we store at most in our session cache.
    pub unreachable_enr_limit: Option<usize>,
}

impl Nat {
    pub fn new(
        listen_sockets: &[SocketAddr],
        local_enr: &Enr,
        ip_mode: IpMode,
        unused_port_range: Option<RangeInclusive<u16>>,
        ban_duration: Option<Duration>,
        session_cache_capacity: usize,
        unreachable_enr_limit: Option<usize>,
    ) -> Self {
        let mut nat = Nat {
            ip_mode,
            is_behind_nat: None,
            new_peer_latest_relay_cache: LruCache::new(session_cache_capacity),
            hole_punch_tracker: HashSetDelay::new(Duration::from_secs(DEFAULT_HOLE_PUNCH_LIFETIME)),
            unused_port_range,
            ban_duration,
            unreachable_enr_limit,
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
                nat.set_is_behind_nat(listen_sockets, Some(ip.into()), port);
            }
            (_, _, Some(ip6), port) => {
                nat.set_is_behind_nat(listen_sockets, Some(ip6.into()), port);
            }
            (None, Some(port), _, _) | (_, _, None, Some(port)) => {
                nat.set_is_behind_nat(listen_sockets, None, Some(port));
            }
            (None, None, None, None) => {}
        }
        nat
    }

    pub fn track(&mut self, peer_socket: SocketAddr) {
        if self.is_behind_nat == Some(false) {
            return;
        }
        self.hole_punch_tracker.insert(peer_socket);
    }

    pub fn untrack(&mut self, peer_socket: &SocketAddr) {
        _ = self.hole_punch_tracker.remove(peer_socket)
    }

    /// Called when a new observed address is reported at start up or after a
    /// [`crate::Discv5Event::SocketUpdated`].
    pub fn set_is_behind_nat(
        &mut self,
        listen_sockets: &[SocketAddr],
        observed_ip: Option<IpAddr>,
        observed_port: Option<u16>,
    ) {
        if !listen_sockets
            .iter()
            .any(|listen_socket| Some(listen_socket.port()) == observed_port)
        {
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

    /// Determines if an ENR is reachable or not based on its assigned keys.
    pub fn is_enr_reachable(enr: &Enr) -> bool {
        enr.udp4_socket().is_some() || enr.udp6_socket().is_some()
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
    use crate::return_if_ipv6_is_not_supported;

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
        return_if_ipv6_is_not_supported!();

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
