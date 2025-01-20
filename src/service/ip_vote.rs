use enr::NodeId;
use fnv::FnvHashMap;
use std::{
    collections::HashMap,
    hash::Hash,
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
    pub fn has_minimum_threshold(&mut self) -> (bool, bool) {
        let instant = Instant::now();
        self.ipv4_votes.retain(|_, v| v.1 > instant);
        self.ipv6_votes.retain(|_, v| v.1 > instant);

        (
            self.ipv4_votes.len() >= self.minimum_threshold,
            self.ipv6_votes.len() >= self.minimum_threshold,
        )
    }

    /// Filter the stale votes and return the majority `SocketAddr` if it exists.
    /// If there are not enough votes to meet the threshold this returns None.
    fn filter_stale_find_most_frequent<K: Copy + Eq + Hash>(
        votes: &HashMap<NodeId, (K, Instant)>,
        minimum_threshold: usize,
    ) -> (HashMap<NodeId, (K, Instant)>, Option<K>) {
        let mut updated = HashMap::default();
        let mut counter: FnvHashMap<K, usize> = FnvHashMap::default();
        let mut max: Option<(K, usize)> = None;
        let now = Instant::now();

        for (node_id, (vote, instant)) in votes {
            // Discard stale votes.
            if instant <= &now {
                continue;
            }
            updated.insert(*node_id, (*vote, *instant));

            let count = counter.entry(*vote).or_default();
            *count += 1;
            let current_max = max.map(|(_v, m)| m).unwrap_or_default();
            if *count >= current_max && *count >= minimum_threshold {
                max = Some((*vote, *count));
            }
        }

        (updated, max.map(|m| m.0))
    }

    /// Returns the majority `SocketAddr`'s of both IPv4 and IPv6 if they exist. If there are not enough votes to meet the threshold this returns None for each stack.
    pub fn majority(&mut self) -> (Option<SocketAddrV4>, Option<SocketAddrV6>) {
        let (updated_ipv4_votes, ipv4_majority) = Self::filter_stale_find_most_frequent::<
            SocketAddrV4,
        >(
            &self.ipv4_votes, self.minimum_threshold
        );
        self.ipv4_votes = updated_ipv4_votes;

        let (updated_ipv6_votes, ipv6_majority) = Self::filter_stale_find_most_frequent::<
            SocketAddrV6,
        >(
            &self.ipv6_votes, self.minimum_threshold
        );
        self.ipv6_votes = updated_ipv6_votes;

        (ipv4_majority, ipv6_majority)
    }
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
