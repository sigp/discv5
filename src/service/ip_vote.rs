use enr::NodeId;
use fnv::FnvHashMap;
use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::{Duration, Instant},
};

/// A collection of IP:Ports for our node reported from external peers.
pub(crate) struct IpVote {
    /// The current collection of IP:Port votes for ipv4.
    ipv4_votes: HashMap<NodeId, (SocketAddrV4, Instant)>,
    /// The current collection of IP:Port votes for ipv6.
    ipv6_votes: HashMap<NodeId, (SocketAddrV6, Instant)>,
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
            ipv4_votes: HashMap::new(),
            ipv6_votes: HashMap::new(),
            minimum_threshold,
            vote_duration,
        }
    }

    pub fn insert(&mut self, key: NodeId, socket: impl Into<SocketAddr>) {
        match socket.into() {
            SocketAddr::V4(socket) => {
                self.ipv4_votes
                    .insert(key, (socket, Instant::now() + self.vote_duration));
            }
            SocketAddr::V6(socket) => {
                self.ipv6_votes
                    .insert(key, (socket, Instant::now() + self.vote_duration));
            }
        }
    }

    /// Returns true if we have more than the minimum number of non-expired votes for a given ip
    /// version.
    pub fn less_than_minimum(&mut self) -> (bool, bool) {
        let instant = Instant::now();
        self.ipv4_votes.retain(|_, v| v.1 > instant);
        self.ipv6_votes.retain(|_, v| v.1 > instant);

        (
            self.ipv4_votes.len() >= self.minimum_threshold,
            self.ipv6_votes.len() >= self.minimum_threshold,
        )
    }

    /// Returns the majority `SocketAddr` if it exists. If there are not enough votes to meet the threshold this returns None.
    pub fn majority(&mut self) -> (Option<SocketAddrV4>, Option<SocketAddrV6>) {
        // remove any expired votes
        let instant = Instant::now();
        self.ipv4_votes.retain(|_, v| v.1 > instant);
        self.ipv6_votes.retain(|_, v| v.1 > instant);

        // Count all the votes into a hashmap containing (socket, count).
        let ip4_count =
            self.ipv4_votes
                .values()
                .fold(FnvHashMap::default(), |mut counts, (socket_vote, _)| {
                    *counts.entry(*socket_vote).or_default() += 1;
                    counts
                });
        let ip6_count =
            self.ipv6_votes
                .values()
                .fold(FnvHashMap::default(), |mut counts, (socket_vote, _)| {
                    *counts.entry(*socket_vote).or_default() += 1;
                    counts
                });

        // find the maximum socket addr
        let ip4_majority = majority(ip4_count.into_iter(), &self.minimum_threshold);
        let ip6_majority = majority(ip6_count.into_iter(), &self.minimum_threshold);
        (ip4_majority, ip6_majority)
    }
}

fn majority<K>(iter: impl Iterator<Item = (K, usize)>, threshold: &usize) -> Option<K> {
    iter.filter(|(_k, count)| count >= threshold)
        .max_by_key(|(_k, count)| *count)
        .map(|(k, _count)| k)
}

#[cfg(test)]
mod tests {
    use super::{Duration, IpVote, NodeId, SocketAddrV4};

    #[test]
    fn test_three_way_vote_draw() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));

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

        assert_eq!(votes.majority(), (Some(socket_2), None));
    }

    #[test]
    fn test_majority_vote() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 3);

        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);

        assert_eq!(votes.majority(), (Some(socket_1), None));
    }

    #[test]
    fn test_below_threshold() {
        let mut votes = IpVote::new(3, Duration::from_secs(10));
        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 3);

        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);

        assert_eq!(votes.majority(), (None, None));
    }
}
