//! This struct keeps track of voting for what our external socket is for both IPv4 and IPv6.
//!
//! Without correct SNAT routing rules, some routers can use alternating or round-robin ports to
//! send outbound traffic. Generally speaking, these ports won't be accessible for inbound traffic
//! from any peers, so they should not be advertised.
//!
//! Therefore the majority function works as follows:
//! - Keep track of all votes within a defined time period (vote_duration)
//! - Prefer a clear majority on the full IP:port when one exists
//! - Otherwise fall back to a clear majority on the IP alone. Competing ports for the same IP do
//!   not block an IP-only result; the caller must pair that IP with a locally known UDP port
//! - A candidate wins only if it meets `minimum_threshold` and no runner-up is within
//!   CLEAR_MAJORITY_PERCENTAGE of it (prevents flip-flopping between competing values)

use enr::NodeId;
use fnv::FnvHashMap;
use std::{
    collections::HashMap,
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::{Duration, Instant},
};
use tracing::debug;

/// To avoid false winners, the majority vote must win by at least this percentage compared to the next
/// likely candidate.
const CLEAR_MAJORITY_PERCENTAGE: f64 = 0.3;

/// Majority vote result for a single IP stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpVoteOutcome<S, I> {
    /// Clear majority on the full IP:port.
    Socket(S),
    /// Clear majority on the IP, without a clear IP:port majority.
    IpOnly(I),
}

type Ipv4VoteOutcome = IpVoteOutcome<SocketAddrV4, Ipv4Addr>;
type Ipv6VoteOutcome = IpVoteOutcome<SocketAddrV6, Ipv6Addr>;
type VoteMap<S> = HashMap<NodeId, (S, Instant)>;
type StackMajority<S, I> = (VoteMap<S>, Option<IpVoteOutcome<S, I>>);

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
            panic!(
                "Setting enr_peer_update_min to a value less than 2 will cause issues with discovery with peers behind NAT"
            );
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

    /// Explicit pruning of old states in the hashamp.
    fn clear_old_votes(&mut self) {
        let instant = Instant::now();
        self.ipv4_votes.retain(|_, v| v.1 > instant);
        self.ipv6_votes.retain(|_, v| v.1 > instant);
    }

    /// Returns true if we have more than the minimum number of non-expired votes for a given ip
    /// version.
    pub fn has_minimum_threshold(&mut self) -> (bool, bool) {
        self.clear_old_votes();
        (
            self.ipv4_votes.len() >= self.minimum_threshold,
            self.ipv6_votes.len() >= self.minimum_threshold,
        )
    }

    /// Drops expired votes and returns the clear majority key, if one exists.
    fn filter_stale_find_most_frequent<K: Copy + Eq + Hash + std::fmt::Debug>(
        votes: &HashMap<NodeId, (K, Instant)>,
        minimum_threshold: usize,
    ) -> (HashMap<NodeId, (K, Instant)>, Option<K>) {
        let now = Instant::now();
        let mut updated = HashMap::default();
        for (node_id, (vote, instant)) in votes {
            if instant <= &now {
                continue;
            }
            updated.insert(*node_id, (*vote, *instant));
        }

        let majority = Self::find_majority_by_key(&updated, minimum_threshold, |vote| vote);
        (updated, majority)
    }

    /// Returns a clear majority over `key_fn(vote)` for non-expired votes, or `None`.
    fn find_majority_by_key<V, K, F>(
        votes: &HashMap<NodeId, (V, Instant)>,
        minimum_threshold: usize,
        mut key_fn: F,
    ) -> Option<K>
    where
        V: Copy,
        K: Copy + Eq + Hash + std::fmt::Debug,
        F: FnMut(V) -> K,
    {
        let mut counter: FnvHashMap<K, usize> = FnvHashMap::default();
        let mut max_count = 0;
        let mut second_max_count = 0;
        let mut max_vote = None;
        let now = Instant::now();

        for (vote, instant) in votes.values() {
            if instant <= &now {
                continue;
            }

            let key = key_fn(*vote);
            let count = counter.entry(key).or_default();
            *count += 1;

            if *count > max_count {
                // Only update second_max if the previous max was from a different vote
                if max_vote.is_some() && max_vote != Some(key) {
                    second_max_count = max_count;
                }
                max_count = *count;
                max_vote = Some(key);
            } else if *count > second_max_count && Some(key) != max_vote {
                second_max_count = *count;
            }
        }

        if max_count >= minimum_threshold {
            let threshold =
                ((max_count as f64) * (1.0 - CLEAR_MAJORITY_PERCENTAGE)).round() as usize;
            // If the second candidate is within CLEAR_MAJORITY_PERCENTAGE of the max, then there
            // is no winner.
            if second_max_count >= threshold {
                debug!(
                    highest_count = max_count,
                    second_highest_count = second_max_count,
                    min_threshold = minimum_threshold,
                    threshold_to_max = threshold,
                    "Competing votes detected."
                );
                None
            } else {
                max_vote
            }
        } else {
            None
        }
    }

    fn majority_for_stack<S, I, F>(
        votes: &VoteMap<S>,
        minimum_threshold: usize,
        ip_of: F,
    ) -> StackMajority<S, I>
    where
        S: Copy + Eq + Hash + std::fmt::Debug,
        I: Copy + Eq + Hash + std::fmt::Debug,
        F: Fn(S) -> I + Copy,
    {
        let (updated_votes, socket_majority) =
            Self::filter_stale_find_most_frequent::<S>(votes, minimum_threshold);

        if let Some(socket) = socket_majority {
            return (updated_votes, Some(IpVoteOutcome::Socket(socket)));
        }

        let ip_majority =
            Self::find_majority_by_key(&updated_votes, minimum_threshold, ip_of)
                .map(IpVoteOutcome::IpOnly);

        (updated_votes, ip_majority)
    }

    /// Returns the IPv4/IPv6 majority outcomes. Prefers a clear IP:port majority, otherwise a
    /// clear IP-only majority. Removes stale votes.
    pub fn majority(&mut self) -> (Option<Ipv4VoteOutcome>, Option<Ipv6VoteOutcome>) {
        let (updated_ipv4_votes, ipv4_majority) = Self::majority_for_stack(
            &self.ipv4_votes,
            self.minimum_threshold,
            |socket: SocketAddrV4| *socket.ip(),
        );
        self.ipv4_votes = updated_ipv4_votes;

        let (updated_ipv6_votes, ipv6_majority) = Self::majority_for_stack(
            &self.ipv6_votes,
            self.minimum_threshold,
            |socket: SocketAddrV6| *socket.ip(),
        );
        self.ipv6_votes = updated_ipv6_votes;

        (ipv4_majority, ipv6_majority)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CLEAR_MAJORITY_PERCENTAGE, Duration, IpVote, IpVoteOutcome, NodeId, SocketAddrV4,
    };
    use quickcheck::{Arbitrary, Gen, TestResult, quickcheck};
    use std::net::Ipv4Addr;

    #[test]
    fn test_three_way_socket_draw_returns_ip_only() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();

        let socket_1 = SocketAddrV4::new(ip, 1);
        let socket_2 = SocketAddrV4::new(ip, 2);
        let socket_3 = SocketAddrV4::new(ip, 3);

        // Three ports tied: no Socket winner, clear IP majority.
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);
        votes.insert(NodeId::random(), socket_3);
        votes.insert(NodeId::random(), socket_3);

        assert_eq!(votes.majority().0, Some(IpVoteOutcome::IpOnly(ip)));
    }

    #[test]
    fn test_majority_vote() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let socket_1 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 2);

        // 5 votes for socket_1, 1 vote for socket_2
        // 1 < (5 * (1-CLEAR_MAJORITY_PERCENTAGE)) = 3.5, so clear majority
        for _ in 0..5 {
            votes.insert(NodeId::random(), socket_1);
        }
        votes.insert(NodeId::random(), socket_2);

        assert_eq!(
            votes.majority(),
            (Some(IpVoteOutcome::Socket(socket_1)), None)
        );
    }

    #[test]
    fn test_below_threshold() {
        let mut votes = IpVote::new(3, Duration::from_secs(10));
        let socket_1 = SocketAddrV4::new("1.1.1.1".parse().unwrap(), 1);
        let socket_2 = SocketAddrV4::new("2.2.2.2".parse().unwrap(), 2);
        let socket_3 = SocketAddrV4::new("3.3.3.3".parse().unwrap(), 3);

        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_1);
        votes.insert(NodeId::random(), socket_2);
        votes.insert(NodeId::random(), socket_3);

        assert_eq!(votes.majority(), (None, None));
    }

    #[test]
    fn test_snat_fluctuation_multiple_iterations() {
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let port_1 = SocketAddrV4::new(ip, 50000);
        let port_2 = SocketAddrV4::new(ip, 50001);

        for iteration in 0..10 {
            let mut votes = IpVote::new(2, Duration::from_secs(10));

            if iteration % 2 == 0 {
                for _ in 0..3 {
                    votes.insert(NodeId::random(), port_1);
                }
                for _ in 0..3 {
                    votes.insert(NodeId::random(), port_2);
                }
            } else {
                for _ in 0..3 {
                    votes.insert(NodeId::random(), port_2);
                }
                for _ in 0..3 {
                    votes.insert(NodeId::random(), port_1);
                }
            }

            assert_eq!(votes.majority().0, Some(IpVoteOutcome::IpOnly(ip)));
        }
    }

    #[test]
    fn test_ip_majority_without_port_majority() {
        const THRESHOLD: usize = 10;
        let mut votes = IpVote::new(THRESHOLD, Duration::from_secs(10));
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();

        for i in 0..THRESHOLD {
            votes.insert(
                NodeId::random(),
                SocketAddrV4::new(ip, 1000 + i as u16),
            );
        }

        assert_eq!(votes.majority().0, Some(IpVoteOutcome::IpOnly(ip)));
    }

    #[test]
    fn test_ip_majority_below_threshold() {
        const THRESHOLD: usize = 10;
        let mut votes = IpVote::new(THRESHOLD, Duration::from_secs(10));
        let ip1: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let ip2: Ipv4Addr = "5.6.7.8".parse().unwrap();

        for i in 0..(THRESHOLD - 1) {
            votes.insert(
                NodeId::random(),
                SocketAddrV4::new(ip1, 1000 + i as u16),
            );
        }
        votes.insert(NodeId::random(), SocketAddrV4::new(ip2, 9000));

        assert_eq!(votes.majority(), (None, None));
    }

    #[test]
    fn test_ip_majority_with_different_ips() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let ip1: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let ip2: Ipv4Addr = "5.6.7.8".parse().unwrap();

        for i in 0..5 {
            votes.insert(
                NodeId::random(),
                SocketAddrV4::new(ip1, 1000 + i as u16),
            );
        }
        votes.insert(NodeId::random(), SocketAddrV4::new(ip2, 1002));

        assert_eq!(votes.majority().0, Some(IpVoteOutcome::IpOnly(ip1)));
    }

    #[test]
    fn test_socket_majority_wins_over_ip_majority() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let ip1: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let ip2: Ipv4Addr = "5.6.7.8".parse().unwrap();
        let winning_socket = SocketAddrV4::new(ip2, 9000);

        // More votes for ip1 overall, but only ip2 has a repeated port.
        for i in 0..3 {
            votes.insert(
                NodeId::random(),
                SocketAddrV4::new(ip1, 1000 + i as u16),
            );
        }
        for _ in 0..5 {
            votes.insert(NodeId::random(), winning_socket);
        }

        assert_eq!(
            votes.majority().0,
            Some(IpVoteOutcome::Socket(winning_socket))
        );
    }

    #[test]
    fn test_competing_ips_return_none() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let ip1: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let ip2: Ipv4Addr = "5.6.7.8".parse().unwrap();

        for i in 0..5 {
            votes.insert(
                NodeId::random(),
                SocketAddrV4::new(ip1, 1000 + i as u16),
            );
            votes.insert(
                NodeId::random(),
                SocketAddrV4::new(ip2, 2000 + i as u16),
            );
        }

        assert_eq!(votes.majority(), (None, None));
    }

    // Property-based test structures
    #[derive(Debug, Clone)]
    struct VoteData {
        port: u16,
        node_id: NodeId,
    }

    impl Arbitrary for VoteData {
        fn arbitrary(g: &mut Gen) -> VoteData {
            VoteData {
                port: u16::arbitrary(g),
                node_id: NodeId::random(),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct VoteScenario {
        votes: Vec<VoteData>,
        threshold: usize,
    }

    impl Arbitrary for VoteScenario {
        fn arbitrary(g: &mut Gen) -> VoteScenario {
            let threshold = (u8::arbitrary(g) % 10 + 2) as usize; // 2-11
            let vote_count = (u8::arbitrary(g) % 20) as usize; // 0-19
            let votes = (0..vote_count).map(|_| VoteData::arbitrary(g)).collect();
            VoteScenario { votes, threshold }
        }
    }

    quickcheck! {
        /// Below threshold on both socket and IP counts returns None.
        fn prop_below_threshold_returns_none(scenario: VoteScenario) -> TestResult {
            if scenario.votes.is_empty() {
                return TestResult::discard();
            }

            let mut vote_system = IpVote::new(scenario.threshold, Duration::from_secs(10));
            let ip = "192.168.1.1".parse().unwrap();

            for vote_data in &scenario.votes {
                let socket = SocketAddrV4::new(ip, vote_data.port);
                vote_system.insert(vote_data.node_id, socket);
            }

            let mut port_counts = std::collections::HashMap::new();
            for vote_data in &scenario.votes {
                *port_counts.entry(vote_data.port).or_insert(0) += 1;
            }

            let max_port_count = port_counts.values().max().copied().unwrap_or(0);
            let total_ip_votes = scenario.votes.len();

            if max_port_count < scenario.threshold && total_ip_votes < scenario.threshold {
                TestResult::from_bool(vote_system.majority().0.is_none())
            } else {
                TestResult::discard()
            }
        }

        /// Clear socket majorities return Socket; otherwise same-IP votes return IpOnly.
        fn prop_clear_socket_winner_selected(scenario: VoteScenario) -> TestResult {
            if scenario.votes.len() < 2 {
                return TestResult::discard();
            }

            let mut vote_system = IpVote::new(scenario.threshold, Duration::from_secs(10));
            let ip = "192.168.1.1".parse().unwrap();

            for vote_data in &scenario.votes {
                let socket = SocketAddrV4::new(ip, vote_data.port);
                vote_system.insert(vote_data.node_id, socket);
            }

            let mut port_counts = std::collections::HashMap::new();
            for vote_data in &scenario.votes {
                *port_counts.entry(vote_data.port).or_insert(0) += 1;
            }

            let mut counts: Vec<_> = port_counts.values().copied().collect();
            counts.sort_by(|a, b| b.cmp(a));

            if counts.is_empty() {
                return TestResult::discard();
            }

            let max_count = counts[0];
            let second_max = counts.get(1).copied().unwrap_or(0);
            let threshold_margin = ((max_count as f64) * (1.0 - CLEAR_MAJORITY_PERCENTAGE)).round() as usize;
            let has_clear_socket_winner = max_count >= scenario.threshold && second_max < threshold_margin;

            let result = vote_system.majority().0;

            if has_clear_socket_winner {
                TestResult::from_bool(matches!(result, Some(IpVoteOutcome::Socket(_))))
            } else if scenario.votes.len() >= scenario.threshold {
                TestResult::from_bool(matches!(result, Some(IpVoteOutcome::IpOnly(_))))
            } else {
                TestResult::from_bool(result.is_none())
            }
        }

        /// Inserting the same node vote repeatedly is idempotent.
        fn prop_same_vote_idempotent(port: u16) -> bool {
            let mut vote_system = IpVote::new(2, Duration::from_secs(10));
            let ip = "192.168.1.1".parse().unwrap();
            let socket = SocketAddrV4::new(ip, port);
            let node_id = NodeId::random();

            vote_system.insert(node_id, socket);
            let result1 = vote_system.majority().0;

            vote_system.insert(node_id, socket);
            let result2 = vote_system.majority().0;

            result1 == result2
        }

        /// Each NodeId contributes at most one vote.
        fn prop_vote_count_bounded_by_nodes() -> bool {
            let mut vote_system = IpVote::new(2, Duration::from_secs(10));
            let ip = "192.168.1.1".parse().unwrap();
            let socket = SocketAddrV4::new(ip, 8080);

            let nodes = [NodeId::random(), NodeId::random(), NodeId::random()];
            for &node_id in &nodes {
                vote_system.insert(node_id, socket);
            }

            matches!(
                vote_system.majority().0,
                Some(IpVoteOutcome::Socket(_))
            )
        }

        /// Competing ports within the margin yield IpOnly for a shared IP.
        fn prop_competition_within_margin_no_socket_winner(threshold: u8, first_votes: u8, second_votes: u8) -> TestResult {
            let threshold = threshold.max(2) as usize;
            let first_votes = first_votes.max(1) as usize;
            let second_votes = second_votes.max(1) as usize;

            if first_votes < threshold || first_votes <= second_votes {
                return TestResult::discard();
            }

            let threshold_margin = ((first_votes as f64) * (1.0 - CLEAR_MAJORITY_PERCENTAGE)).round() as usize;
            if second_votes < threshold_margin {
                return TestResult::discard();
            }

            let mut votes = IpVote::new(threshold, Duration::from_secs(10));
            let ip = "192.168.1.1".parse().unwrap();
            let socket1 = SocketAddrV4::new(ip, 8080);
            let socket2 = SocketAddrV4::new(ip, 8081);

            for _ in 0..first_votes {
                votes.insert(NodeId::random(), socket1);
            }
            for _ in 0..second_votes {
                votes.insert(NodeId::random(), socket2);
            }

            let total = first_votes + second_votes;
            let result = votes.majority().0;
            if total >= threshold {
                TestResult::from_bool(result == Some(IpVoteOutcome::IpOnly(ip)))
            } else {
                TestResult::from_bool(result.is_none())
            }
        }

        /// Clear socket winner when the runner-up is outside the margin.
        fn prop_clear_winner_outside_margin(threshold: u8, first_votes: u8, second_votes: u8) -> TestResult {
            let threshold = threshold.max(2) as usize;
            let first_votes = first_votes.max(1) as usize;
            let second_votes = second_votes as usize;

            if first_votes < threshold {
                return TestResult::discard();
            }

            let threshold_margin = ((first_votes as f64) * (1.0 - CLEAR_MAJORITY_PERCENTAGE)).round() as usize;
            if second_votes >= threshold_margin {
                return TestResult::discard();
            }

            let mut votes = IpVote::new(threshold, Duration::from_secs(10));
            let ip = "192.168.1.1".parse().unwrap();
            let socket1 = SocketAddrV4::new(ip, 8080);
            let socket2 = SocketAddrV4::new(ip, 8081);

            for _ in 0..first_votes {
                votes.insert(NodeId::random(), socket1);
            }
            for _ in 0..second_votes {
                votes.insert(NodeId::random(), socket2);
            }

            TestResult::from_bool(votes.majority().0 == Some(IpVoteOutcome::Socket(socket1)))
        }
    }

    #[test]
    fn test_exact_threshold_boundary() {
        let mut votes = IpVote::new(3, Duration::from_secs(10));
        let ip = "192.168.1.1".parse().unwrap();
        let socket1 = SocketAddrV4::new(ip, 8080);
        let socket2 = SocketAddrV4::new(ip, 8081);

        for _ in 0..3 {
            votes.insert(NodeId::random(), socket1);
        }
        votes.insert(NodeId::random(), socket2);

        assert_eq!(
            votes.majority().0,
            Some(IpVoteOutcome::Socket(socket1))
        );
    }

    #[test]
    fn test_competing_votes_within_margin() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let socket1 = SocketAddrV4::new(ip, 8080);
        let socket2 = SocketAddrV4::new(ip, 8081);

        // 10 vs 8 is within CLEAR_MAJORITY_PERCENTAGE: no Socket winner.
        for _ in 0..10 {
            votes.insert(NodeId::random(), socket1);
        }
        for _ in 0..8 {
            votes.insert(NodeId::random(), socket2);
        }

        assert_eq!(votes.majority().0, Some(IpVoteOutcome::IpOnly(ip)));
    }

    #[test]
    fn test_clear_majority_outside_margin() {
        let mut votes = IpVote::new(5, Duration::from_secs(10));
        let ip = "192.168.1.1".parse().unwrap();
        let socket1 = SocketAddrV4::new(ip, 8080);
        let socket2 = SocketAddrV4::new(ip, 8081);

        // 10 vs 4 is outside the margin, so socket1 wins.
        for _ in 0..10 {
            votes.insert(NodeId::random(), socket1);
        }
        for _ in 0..4 {
            votes.insert(NodeId::random(), socket2);
        }

        assert_eq!(
            votes.majority().0,
            Some(IpVoteOutcome::Socket(socket1))
        );
    }

    #[test]
    fn test_three_way_competition() {
        let mut votes = IpVote::new(2, Duration::from_secs(10));
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let socket1 = SocketAddrV4::new(ip, 8080);
        let socket2 = SocketAddrV4::new(ip, 8081);
        let socket3 = SocketAddrV4::new(ip, 8082);

        for _ in 0..5 {
            votes.insert(NodeId::random(), socket1);
            votes.insert(NodeId::random(), socket2);
            votes.insert(NodeId::random(), socket3);
        }

        assert_eq!(votes.majority().0, Some(IpVoteOutcome::IpOnly(ip)));
    }
}
