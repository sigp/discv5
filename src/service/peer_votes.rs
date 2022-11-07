use crate::ConnectionDirection;
use enr::NodeId;
use fnv::FnvHashMap;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub enum Address {
    Reachable(SocketAddr),
    SymmetricNAT(IpAddr),
}

/// The time to keep track of incoming connections. This is used to determine if we are behind a
/// NAT or not.
const INCOMING_CONNECTION_RETAIN_DURATION: Duration = Duration::from_secs(60);

/// A collection of IP:Ports for our node reported from peers.
pub(crate) struct PeerVotes {
    /// The minimum number of votes required before an IP/PORT is accepted.
    minimum_threshold_ip: usize,
    /// The minimum number of peers required before we consider making a decision about our NAT
    /// status.
    minimum_threshold_nat: usize,
    /// The time votes remain valid for IP voting.
    vote_duration_ip: Duration,
    /// Keeps track of the most recent incoming connections, to make a decision about whether we
    /// are behind a NAT or not.
    incoming_connections: VecDeque<Instant>,
    /// The current collection of IP:Port votes.
    votes: HashMap<NodeId, (SocketAddr, Instant)>,
    /// Find out if this node is behind a symmetric NAT, if so this node will
    /// not be passed on to other peers in NODES responses, hence only have the
    /// connections that it initiates. Should only be true if the NAT traversal
    /// protocol version is supported.
    include_symmetric_nat: bool,
}

impl PeerVotes {
    pub fn new(
        minimum_threshold_ip: usize,
        minimum_threshold_nat: usize,
        vote_duration_ip: Duration,
        include_symmetric_nat: bool,
    ) -> Self {
        PeerVotes {
            minimum_threshold_ip,
            minimum_threshold_nat,
            vote_duration_ip,
            include_symmetric_nat,
            votes: HashMap::with_capacity(20),
            incoming_connections: VecDeque::new(),
        }
    }

    /// Inserts a socket address that another peer has witnessed packets from us. Each entry counts as a "vote".
    pub fn register_ip_vote(&mut self, key: NodeId, socket: impl Into<SocketAddr>) {
        self.votes
            .insert(key, (socket.into(), Instant::now() + self.vote_duration_ip));
    }

    /// Registers a new incoming connection that has been established.
    pub fn register_incoming_connection(&mut self) {
        self.remove_expired_incoming_connection_cache();
        self.incoming_connections.push_back(Instant::now());
    }

    /// Makes a best-guess if we are behind a NAT or not. It uses recently connected incoming peers
    /// and the number of incoming peers connected in the routing table to determine this.
    pub fn is_behind_nat(
        &mut self,
        connections: impl Iterator<Item = ConnectionDirection>,
    ) -> bool {
        self.remove_expired_incoming_connection_cache();

        if !self.incoming_connections.is_empty() {
            // We have recent incoming connections, network is not behind a NAT and working as
            // expected.
            return false;
        }

        let mut node_count = 0;
        for connection in connections {
            if let ConnectionDirection::Incoming = connection {
                // If we have at least one incoming connection in our table, lets say that we are
                // not NATd
                return false;
            }
            node_count += 1;
        }
        // If we don't have enough nodes to properly check, assume network is fine and we are
        // not behind a NAT.
        // If our entire table is filled with external connections and there have been no
        // recent incoming connections, we assume we are behind a NAT.
        node_count >= self.minimum_threshold_nat
    }

    /// Returns the majority `SocketAddr` if it exists, otherwise if include_symmetric_nat
    /// is set to true the majority `IpAddr` if it exists. If there are not enough votes to
    /// meet the threshold this returns None.
    pub fn current_majority_ip(&mut self) -> (Option<Address>, Option<Address>) {
        // remove any expired votes
        let instant = Instant::now();
        self.votes.retain(|_, v| v.1 > instant);

        // count votes for socket addresses
        let mut ip4_count: FnvHashMap<SocketAddrV4, usize> = FnvHashMap::default();
        let mut ip6_count: FnvHashMap<SocketAddrV6, usize> = FnvHashMap::default();

        // count votes for ip addresses only
        let mut ip4_count_symm_nat: FnvHashMap<Ipv4Addr, usize> = FnvHashMap::default();
        let mut ip6_count_symm_nat: FnvHashMap<Ipv6Addr, usize> = FnvHashMap::default();

        for (socket, _) in self.votes.values() {
            // NOTE: here we depend on addresses being already cleaned up. No mapped or compat
            // addresses should be present. This is done in the codec.
            match socket {
                SocketAddr::V4(socket) => {
                    *ip4_count.entry(*socket).or_insert_with(|| 0) += 1;
                    if self.include_symmetric_nat {
                        *ip4_count_symm_nat.entry(*socket.ip()).or_insert_with(|| 0) += 1;
                    }
                }
                SocketAddr::V6(socket) => {
                    *ip6_count.entry(*socket).or_insert_with(|| 0) += 1;
                    if self.include_symmetric_nat {
                        *ip6_count_symm_nat.entry(*socket.ip()).or_insert_with(|| 0) += 1;
                    }
                }
            }
        }

        // find the maximum socket addr
        let ip4_majority = majority(ip4_count.into_iter(), &self.minimum_threshold_ip)
            .map(|address| Address::Reachable(SocketAddr::V4(address)));
        let ip6_majority = majority(ip6_count.into_iter(), &self.minimum_threshold_ip)
            .map(|address| Address::Reachable(SocketAddr::V6(address)));

        // If a majority socket address is found this is an indication that this node has a discv5 network
        // configuration that makes it WAN reachable.
        if ip4_majority.is_some() || ip6_majority.is_some() {
            (ip4_majority, ip6_majority)
        } else if self.include_symmetric_nat {
            // If no majority socket address can be found, try to find a majority ip address. If it exists this is
            // an indication that this node is behind a NAT.

            // find the maximum ip addr
            let ip4_majority_nat =
                majority(ip4_count_symm_nat.into_iter(), &self.minimum_threshold_ip)
                    .map(|address| Address::SymmetricNAT(IpAddr::V4(address)));
            let ip6_majority_nat =
                majority(ip6_count_symm_nat.into_iter(), &self.minimum_threshold_ip)
                    .map(|address| Address::SymmetricNAT(IpAddr::V6(address)));

            (ip4_majority_nat, ip6_majority_nat)
        } else {
            (None, None)
        }
    }

    /// Clears out-dated incoming connection cache.
    fn remove_expired_incoming_connection_cache(&mut self) {
        // Connections are stored in monotonically increasing times. We just remove the first
        // elements until we reach the timeout.
        let now = Instant::now();
        while let Some(time) = self.incoming_connections.pop_front() {
            if time + INCOMING_CONNECTION_RETAIN_DURATION <= now {
                self.incoming_connections.push_front(time);
                break;
            }
        }
    }
}

fn majority<K>(iter: impl Iterator<Item = (K, usize)>, threshold: &usize) -> Option<K> {
    iter.filter(|(_k, count)| count >= threshold)
        .max_by_key(|(_k, count)| *count)
        .map(|(k, _count)| k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_three_way_vote_draw() {
        let mut votes = PeerVotes::new(2, 2, Duration::from_secs(10), false);

        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 3);

        // 3 votes for each socket
        votes.register_ip_vote(NodeId::random(), socket_1);
        votes.register_ip_vote(NodeId::random(), socket_1);
        votes.register_ip_vote(NodeId::random(), socket_1);
        votes.register_ip_vote(NodeId::random(), socket_2);
        votes.register_ip_vote(NodeId::random(), socket_2);
        votes.register_ip_vote(NodeId::random(), socket_2);
        votes.register_ip_vote(NodeId::random(), socket_3);
        votes.register_ip_vote(NodeId::random(), socket_3);
        votes.register_ip_vote(NodeId::random(), socket_3);

        let (socket4, socket6) = votes.current_majority_ip();
        assert_eq!(socket4, Some(Address::Reachable(SocketAddr::V4(socket_2))));
        assert_eq!(socket6, None);
    }

    #[test]
    fn test_majority_vote() {
        let mut votes = PeerVotes::new(2, 2, Duration::from_secs(10), false);
        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 3);

        votes.register_ip_vote(NodeId::random(), socket_1);
        votes.register_ip_vote(NodeId::random(), socket_1);
        votes.register_ip_vote(NodeId::random(), socket_2);
        votes.register_ip_vote(NodeId::random(), socket_3);

        let (socket4, socket6) = votes.current_majority_ip();
        assert_eq!(socket4, Some(Address::Reachable(SocketAddr::V4(socket_1))));
        assert_eq!(socket6, None);
    }

    #[test]
    fn test_below_threshold() {
        let mut votes = PeerVotes::new(3, 2, Duration::from_secs(10), false);
        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 3);

        votes.register_ip_vote(NodeId::random(), socket_1);
        votes.register_ip_vote(NodeId::random(), socket_1);
        votes.register_ip_vote(NodeId::random(), socket_2);
        votes.register_ip_vote(NodeId::random(), socket_3);

        let (socket4, socket6) = votes.current_majority_ip();
        assert_eq!(socket4, None);
        assert_eq!(socket6, None);
    }
}
