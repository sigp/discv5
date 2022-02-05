use enr::NodeId;
use fnv::FnvHashMap;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

/// A collection of IP:Ports for our node reported from external peers.
pub(crate) struct IpVote {
    /// The current collection of IP:Port votes for ipv4 addresses.
    votes: HashMap<NodeId, (SocketAddr, Instant)>,
    /// The minimum number of votes required before an IP/PORT is accepted.
    minimum_threshold: usize,
    /// The time votes remain valid.
    vote_duration: Duration,
}

impl IpVote {
    pub fn new(minimum_threshold: usize, vote_duration: Duration) -> Self {
        // do not allow minimum thresholds less than 2
        if minimum_threshold < 2 {
            panic!("Setting enr_peer_update_min to a value less than 2 will cause issues with discovery with peers behind NAT");
        }
        IpVote {
            votes: HashMap::new(),
            minimum_threshold,
            vote_duration,
        }
    }

    pub fn insert(&mut self, key: NodeId, socket: SocketAddr) {
        self.votes
            .insert(key, (socket, Instant::now() + self.vote_duration));
    }

    /// Returns the majority `SocketAddr` if it exists. If there are not enough votes to meet the threshold this returns None.
    pub fn majority(&mut self) -> (Option<SocketAddrV4>, Option<SocketAddrV6>) {
        // remove any expired votes
        let instant = Instant::now();
        self.votes.retain(|_, v| v.1 > instant);

        // count votes, take majority
        let mut ipv4_count: FnvHashMap<SocketAddrV4, usize> = FnvHashMap::default();
        let mut ipv6_count: FnvHashMap<SocketAddrV6, usize> = FnvHashMap::default();
        for (socket, _) in self.votes.values() {
            let port = socket.port();
            let (maybe_ipv4, ipv6) = match socket.ip() {
                IpAddr::V4(ipv4) => (Some(ipv4), ipv4.to_ipv6_mapped()),
                IpAddr::V6(ipv6) => (ipv6.to_ipv4(), ipv6), // to_ipv4_mapped() is experimental
            };
            if let Some(ipv4) = maybe_ipv4 {
                *ipv4_count
                    .entry(SocketAddrV4::new(ipv4, port))
                    .or_insert_with(|| 0) += 1;
            }
            *ipv6_count
                .entry(SocketAddrV6::new(ipv6, port, 0, 0))
                .or_insert_with(|| 0) += 1;
        }

        // find the maximum socket addr
        let best_ipv4 = ipv4_count
            .into_iter()
            .filter(|v| v.1 >= self.minimum_threshold)
            .max_by_key(|v| v.1)
            .map(|v| v.0);
        let best_ipv6 = ipv6_count
            .into_iter()
            .filter(|v| v.1 >= self.minimum_threshold)
            .max_by_key(|v| v.1)
            .map(|v| v.0);

        (best_ipv4, best_ipv6)
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, IpVote, NodeId, SocketAddr, SocketAddrV4};

    #[test]
    fn test_three_way_vote_draw() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));

        let socket_1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 1);
        let best = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_2 = SocketAddr::V4(best);
        let socket_3 = SocketAddr::new("127.0.0.1".parse().unwrap(), 3);

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

        assert_eq!(votes.majority(), (Some(best), None));
    }

    #[test]
    fn test_majority_vote() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let best = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_1 = SocketAddr::V4(best);
        let socket_2 = SocketAddr::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddr::new("127.0.0.1".parse().unwrap(), 3);

        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);

        assert_eq!(votes.majority(), (Some(best), None));
    }

    #[test]
    fn test_below_threshold() {
        let mut votes = IpVote::new(3, Duration::from_secs(10));
        let socket_1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddr::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddr::new("127.0.0.1".parse().unwrap(), 3);

        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);

        assert_eq!(votes.majority(), (None, None));
    }
}
