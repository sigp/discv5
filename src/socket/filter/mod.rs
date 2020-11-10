//! A filter which decides whether to accept/reject incoming UDP packets.

use crate::{discv5::PERMIT_BAN_LIST, metrics::METRICS, node_info::NodeAddress, packet::Packet};
use cache::ReceivedPacketCache;
use enr::NodeId;
use std::{collections::HashMap, net::SocketAddr, sync::atomic::Ordering};
use tracing::{debug, warn};

mod cache;
mod config;
pub use config::{FilterConfig, FilterConfigBuilder};

/// The maximum percentage of our unsolicited requests per second limit a node is able to consume
/// for  `NUMBER_OF_WINDOWS` duration before being banned.
/// This allows us to ban the IP/NodeId of an attacker spamming us with requests.
const MAX_PERCENT_OF_LIMIT_PER_NODE: f64 = 0.9;
/// The number of windows to remember before banning a node.
const NUMBER_OF_WINDOWS: usize = 5;

/// The packet filter which decides whether we accept or reject incoming packets.
pub(crate) struct Filter {
    /// Configuration for the packet filter.
    config: FilterConfig,
    /// An ordered (by time) collection of recently seen packets by SocketAddr. The packet data is not
    /// stored here. This stores a 5 seconds of history to calculate a 5 second moving average for
    /// the metrics.
    raw_packets_received: ReceivedPacketCache<SocketAddr>,
    /// An ordered (by time) collection of seen NodeIds that have passed the first filter check and
    /// have an associated NodeId.
    received_by_node: ReceivedPacketCache<NodeId>,
}

impl Filter {
    pub fn new(config: &FilterConfig) -> Filter {
        Filter {
            config: config.clone(),
            raw_packets_received: ReceivedPacketCache::new(
                config.max_requests_per_second,
                METRICS.moving_window,
            ),
            received_by_node: ReceivedPacketCache::new(
                config.max_requests_per_second * NUMBER_OF_WINDOWS,
                METRICS.moving_window,
            ),
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
                        debug!(
                            "Dropped unsolicited packet from IP rate limit: {:?}",
                            src.ip()
                        );
                        return false;
                    }
                }
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
            // The unsolicited filter via IP should ensure this is never reached.
            if !self.received_by_node.cache_insert(node_address.node_id) {
                warn!("Message rejected as reached the maximum request limit for NodeId's");
                return false;
            }

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
                PERMIT_BAN_LIST
                    .write()
                    .ban_nodes
                    .insert(node_address.node_id);
                return false;
            }
        }

        true
    }
}
