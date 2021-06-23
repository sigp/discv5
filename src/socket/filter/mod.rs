//! A filter which decides whether to accept/reject incoming UDP packets.

use crate::{discv5::PERMIT_BAN_LIST, metrics::METRICS, node_info::NodeAddress, packet::Packet};
use cache::ReceivedPacketCache;
use enr::NodeId;
use lru::LruCache;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

mod cache;
mod config;
pub use config::{FilterConfig, FilterConfigBuilder};

/// The maximum percentage of our unsolicited requests per second limit a node is able to consume
/// for `NUMBER_OF_WINDOWS` duration before being banned.
/// This allows us to ban the IP/NodeId of an attacker spamming us with requests.
const MAX_PERCENT_OF_LIMIT_PER_NODE: f64 = 0.9;
/// The maximum number of IPs to retain when calculating the number of nodes per IP.
const KNOWN_ADDRS_SIZE: usize = 500;
/// The number of IPs to retain at any given time that have banned nodes.
const BANNED_NODES_SIZE: usize = 50;

/// The packet filter which decides whether we accept or reject incoming packets.
pub(crate) struct Filter {
    /// Configuration for the packet filter.
    config: FilterConfig,
    /// The duration that bans by this filter last.
    ban_duration: Option<Duration>,
    /// An ordered (by time) collection of recently seen packets by SocketAddr. The packet data is not
    /// stored here. This stores 5 seconds of history to calculate a 5 second moving average for
    /// the metrics.
    raw_packets_received: ReceivedPacketCache<SocketAddr>,
    /// An ordered (by time) collection of seen NodeIds that have passed the first filter check and
    /// have an associated NodeId.
    received_by_node: ReceivedPacketCache<NodeId>,
    /// Keep track of node ids per socket. If someone is using too many node-ids per IP, they can
    /// be banned.
    known_addrs: LruCache<IpAddr, HashSet<NodeId>>,
    /// Keep track of Ips that have banned nodes. If a single IP has many nodes that get banned,
    /// then we ban the IP address.
    banned_nodes: LruCache<IpAddr, usize>,
}

impl Filter {
    pub fn new(config: &FilterConfig, ban_duration: Option<Duration>) -> Filter {
        let max_requests_per_node = config
            .max_requests_per_node_per_second
            .map(|v| v.round() as usize)
            .unwrap_or(config.max_requests_per_second);

        Filter {
            config: config.clone(),
            raw_packets_received: ReceivedPacketCache::new(
                config.max_requests_per_second,
                METRICS.moving_window,
            ),
            received_by_node: ReceivedPacketCache::new(
                max_requests_per_node,
                METRICS.moving_window,
            ),
            known_addrs: LruCache::new(KNOWN_ADDRS_SIZE),
            banned_nodes: LruCache::new(BANNED_NODES_SIZE),
            ban_duration,
        }
    }

    /// The first check. This determines if a new UDP packet should be decoded or dropped.
    /// Only unsolicited packets arrive here.
    pub fn initial_pass(&mut self, src: &SocketAddr) -> bool {
        if PERMIT_BAN_LIST.read().permit_ips.get(&src.ip()).is_some() {
            return true;
        }

        if PERMIT_BAN_LIST.read().ban_ips.get(&src.ip()).is_some() {
            debug!("Dropped unsolicited packet from banned src: {:?}", src);
            return false;
        }

        // Add the un-solicited request to the cache
        // If this is over the maximum requests per ENFORCED_SIZE_TIME, it will be rejected and return false.
        let result = self.raw_packets_received.cache_insert(*src);

        // build the metrics
        METRICS
            .unsolicited_requests_per_window
            .store(self.raw_packets_received.len(), Ordering::Relaxed);

        // It might not be worth the effort keeping an average for the metrics in the cache.
        // Builds the hashmap of IPs to requests
        let hashmap = {
            let mut hashmap = HashMap::with_capacity(10);
            for ip in self
                .raw_packets_received
                .iter()
                .map(|packet| packet.content.ip())
            {
                *hashmap.entry(ip).or_default() += 1.0 / (METRICS.moving_window as f64);
            }
            hashmap
        };
        *METRICS.requests_per_ip_per_second.write() = hashmap;

        // run the filters
        if self.config.enabled {
            // if there is a restriction per IP, enforce it
            if let Some(max_requests_per_ip_per_second) = self.config.max_requests_per_ip_per_second
            {
                if let Some(requests) = METRICS.requests_per_ip_per_second.read().get(&src.ip()) {
                    if requests >= &max_requests_per_ip_per_second {
                        warn!("Banning IP for excessive requests: {:?}", src.ip());
                        // Ban the IP address
                        let ban_timeout = self.ban_duration.map(|v| Instant::now() + v);
                        PERMIT_BAN_LIST
                            .write()
                            .ban_ips
                            .insert(src.ip(), ban_timeout);
                        return false;
                    }
                }
            }
            if !result {
                debug!("Dropped unsolicited packet from RPC limit: {:?}", src.ip());
            }
            result // filter based on whether the packet could get added to the cache or not
        } else {
            true
        }
    }

    pub fn final_pass(&mut self, node_address: &NodeAddress, _packet: &Packet) -> bool {
        if PERMIT_BAN_LIST
            .read()
            .permit_nodes
            .get(&node_address.node_id)
            .is_some()
        {
            return true;
        }

        if PERMIT_BAN_LIST
            .read()
            .ban_nodes
            .get(&node_address.node_id)
            .is_some()
        {
            debug!(
                "Dropped unsolicited packet from banned node_id: {}",
                node_address
            );
            return false;
        }

        if self.config.enabled {
            // Add the un-solicited request to the cache
            // If this is over the maximum requests per ENFORCED_SIZE_TIME, it will be rejected and return false.
            let cache_insert_result = self.received_by_node.cache_insert(node_address.node_id);

            // If a single node has used > MAX_PERCENT_OF_LIMIT_PER_NODE of unsolicited
            // requests, ban them.
            // If we have reached our maximum limit each time, the maximum number of messages is:
            // max_requests_per_second*METRICS.moving_window.
            if self
                .received_by_node
                .iter()
                .filter(|x| x.content == node_address.node_id)
                .count() as f64
                > self.config.max_requests_per_second as f64
                    * METRICS.moving_window as f64
                    * MAX_PERCENT_OF_LIMIT_PER_NODE
            {
                warn!(
                    "Node has exceeded its request limit and is now banned {}",
                    node_address.node_id
                );

                // The node is being banned
                let ban_timeout = self.ban_duration.map(|v| Instant::now() + v);
                PERMIT_BAN_LIST
                    .write()
                    .ban_nodes
                    .insert(node_address.node_id, ban_timeout.clone());

                // If we are tracking banned nodes per IP, add to the count. If the count is higher
                // than our tolerance, ban the IP.
                if let Some(max_bans_per_ip) = self.config.max_bans_per_ip {
                    let ip = node_address.socket_addr.ip();
                    if let Some(banned_count) = self.banned_nodes.get_mut(&ip) {
                        *banned_count += 1;
                        if *banned_count >= max_bans_per_ip {
                            PERMIT_BAN_LIST
                                .write()
                                .ban_ips
                                .insert(ip, ban_timeout.clone());
                        }
                    } else {
                        self.banned_nodes.put(ip, 0);
                    }
                }

                return false;
            }

            if !cache_insert_result {
                warn!(
                    "Message rejected as reached the maximum request limit for node: {}",
                    node_address
                );
                return false;
            }

            // Check the nodes per IP filter configuration
            if let Some(max_nodes_per_ip) = self.config.max_nodes_per_ip {
                // This option is set, store the known nodes per IP.
                let ip = node_address.socket_addr.ip();
                let known_nodes = {
                    if let Some(known_nodes) = self.known_addrs.get_mut(&ip) {
                        known_nodes.insert(node_address.node_id);
                        known_nodes.len()
                    } else {
                        let mut ids = HashSet::new();
                        ids.insert(node_address.node_id);
                        self.known_addrs.put(ip, ids);
                        1
                    }
                };

                if known_nodes >= max_nodes_per_ip {
                    warn!("IP has exceeded its node-id limit and is now banned {}", ip);
                    // The node is being banned
                    let ban_timeout = self.ban_duration.map(|v| Instant::now() + v);
                    PERMIT_BAN_LIST.write().ban_ips.insert(ip, ban_timeout);
                    self.known_addrs.pop(&ip);
                    return false;
                }
            }
        }

        true
    }
}
