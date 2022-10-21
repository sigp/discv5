use crate::ConnectionDirection;
use enr::NodeId;
use fnv::FnvHashMap;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub enum Address {
    Reachable(SocketAddr),
    SymmetricNAT(IpAddr),
}

/// A collection of votes regarding the state of our node reported from peers.
pub(crate) struct PeerVote {
    /// The minimum number of votes required before an IP/PORT is accepted.
    minimum_threshold: usize,
    /// The time votes remain valid.
    vote_duration: Duration,
}

impl PeerVote {
    pub fn new(minimum_threshold: usize, vote_duration: Duration) -> Self {
        // do not allow minimum thresholds less than 2
        if minimum_threshold < 2 {
            panic!("Setting enr_peer_update_min to a value less than 2 will cause issues with discovery with peers behind NAT");
        }
        PeerVote {
            minimum_threshold,
            vote_duration,
        }
    }
}

/// A collection of IP:Ports for our node reported from peers.
pub(crate) struct IpVote {
    vote_config: PeerVote,
    /// The current collection of IP:Port votes.
    votes: HashMap<NodeId, (SocketAddr, Instant)>,
    /// Find out if this node is behind a symmetric NAT, if so this nodes will
    /// not be passed on to other peers in NODES responses, hence only have the
    /// connections that it initiates. Should only be true if the NAT traversal
    /// protocol version is supported.
    include_symmetric_nat: bool,
}

impl IpVote {
    pub fn new(
        minimum_threshold: usize,
        vote_duration: Duration,
        include_symmetric_nat: bool,
    ) -> Self {
        // do not allow minimum thresholds less than 2
        if minimum_threshold < 2 {
            panic!("Setting enr_peer_update_min to a value less than 2 will cause issues with discovery with peers behind NAT");
        }
        IpVote {
            vote_config: PeerVote::new(minimum_threshold, vote_duration),
            include_symmetric_nat,
            votes: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: NodeId, socket: impl Into<SocketAddr>) {
        self.votes.insert(
            key,
            (
                socket.into(),
                Instant::now() + self.vote_config.vote_duration,
            ),
        );
    }

    /// Returns the majority `SocketAddr` if it exists, otherwise if include_symmetric_nat
    /// is set to true the majority `IpAddr` if it exists. If there are not enough votes to
    /// meet the threshold this returns None.
    pub fn vote(&mut self) -> (Option<Address>, Option<Address>) {
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
        let ip4_majority = majority(ip4_count.into_iter(), &self.vote_config.minimum_threshold)
            .map(|address| Address::Reachable(SocketAddr::V4(address)));
        let ip6_majority = majority(ip6_count.into_iter(), &self.vote_config.minimum_threshold)
            .map(|address| Address::Reachable(SocketAddr::V6(address)));

        // If a majority socket address is found this is an indication that this node has a discv5 network
        // configuration that makes it WAN reachable.
        if ip4_majority.is_some() || ip6_majority.is_some() {
            return (ip4_majority, ip6_majority);
        }

        if self.include_symmetric_nat {
            // If no majority socket address can be found, try to find a majority ip address. If it exists this is
            // and indication that this node is behind a NAT.

            // find the maximum ip addr
            let ip4_majority_nat = majority(
                ip4_count_symm_nat.into_iter(),
                &self.vote_config.minimum_threshold,
            )
            .map(|address| Address::SymmetricNAT(IpAddr::V4(address)));
            let ip6_majority_nat = majority(
                ip6_count_symm_nat.into_iter(),
                &self.vote_config.minimum_threshold,
            )
            .map(|address| Address::SymmetricNAT(IpAddr::V6(address)));

            return (ip4_majority_nat, ip6_majority_nat);
        }
        (None, None)
    }
}

fn majority<K>(iter: impl Iterator<Item = (K, usize)>, threshold: &usize) -> Option<K> {
    iter.filter(|(_k, count)| count >= threshold)
        .max_by_key(|(_k, count)| *count)
        .map(|(k, _count)| k)
}

/// A collection counting incoming RELAYREQUESTs from peers.
pub(crate) struct AsymmNatVote {
    /// The current collection of incoming RELAYREQUESTs.
    vote_config: PeerVote,
}

impl AsymmNatVote {
    pub fn new(minimum_threshold: usize, vote_duration: Duration) -> Self {
        AsymmNatVote {
            vote_config: PeerVote::new(minimum_threshold, vote_duration),
        }
    }

    pub fn vote(
        &mut self,
        connections: impl Iterator<Item = ConnectionDirection>,
    ) -> Option<ConnectionDirection> {
        let mut vote_count = 0;

        for conn_dir in connections {
            // Even if timed out requests to this node have lead peers to initiate the NAT
            // traversal protocol with this node before it advertises in its ENR that it is
            // behind an asymmetric NAT, a hole-punch will always be achieved with a dial out
            // resulting in a ConnectionDirection::Outgoing.
            if let ConnectionDirection::Incoming = conn_dir {
                return Some(conn_dir);
            }
            vote_count += 1;
        }
        if vote_count < self.vote_config.minimum_threshold {
            // We haven't got enough kbucket entries yet to vote
            None
        } else {
            Some(ConnectionDirection::Outgoing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_three_way_vote_draw() {
        let mut votes = IpVote::new(2, Duration::from_secs(10), false);

        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 3);

        // 3 votes for each socket
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);
        votes.insert(NodeId::random(), socket_3);
        votes.insert(NodeId::random(), socket_3);

        let (socket4, socket6) = votes.vote();
        assert_eq!(socket4, Some(Address::Reachable(SocketAddr::V4(socket_2))));
        assert_eq!(socket6, None);
    }

    #[test]
    fn test_majority_vote() {
        let mut votes = IpVote::new(2, Duration::from_secs(10), false);
        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 3);

        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);

        let (socket4, socket6) = votes.vote();
        assert_eq!(socket4, Some(Address::Reachable(SocketAddr::V4(socket_1))));
        assert_eq!(socket6, None);
    }

    #[test]
    fn test_below_threshold() {
        let mut votes = IpVote::new(3, Duration::from_secs(10), false);
        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 3);

        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);

        let (socket4, socket6) = votes.vote();
        assert_eq!(socket4, None);
        assert_eq!(socket6, None);
    }
}
