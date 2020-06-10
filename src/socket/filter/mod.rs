//! A filter which decides whether to accept/reject incoming UDP packets.

use crate::packet::Packet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

mod cache;
mod config;

use crate::discv5::PERMIT_BAN_LIST;
use crate::metrics::METRICS;
use cache::ReceivedPacketCache;
pub use config::{FilterConfig, FilterConfigBuilder};
use log::debug;
use std::collections::HashMap;

/// The packet filter which decides whether we accept or reject incoming packets.
pub(crate) struct Filter {
    /// Configuration for the packet filter.
    config: FilterConfig,
    /// An ordered (by time) collection of recently seen packets by SocketAddr. The packet data is not
    /// stored here. This stores a 5 seconds of history to calculate a 5 second moving average for
    /// the metrics.
    raw_packets_received: ReceivedPacketCache<SocketAddr>,
    /// An ordered (by time) collection of seen packets that have passed the first filter check and
    /// have an associated NodeId.
    _packets_received: ReceivedPacketCache<(SocketAddr, Packet)>,
}

impl Filter {
    pub fn new(config: &FilterConfig) -> Filter {
        Filter {
            config: config.clone(),
            raw_packets_received: ReceivedPacketCache::new(
                config.max_requests_per_second,
                METRICS.moving_window,
            ),
            _packets_received: ReceivedPacketCache::new(
                config.max_requests_per_second,
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
        let result = self.raw_packets_received.insert_reset(src.clone());

        // build the metrics
        METRICS
            .unsolicited_requests_per_window
            .store(self.raw_packets_received.len(), Ordering::Relaxed);

        // TODO: Bench the performance of this
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

    pub fn final_pass(&mut self, _src: &SocketAddr, _packet: &Packet) -> bool {
        // let allow_deny_list = self.allow_deny_list.read();

        // if there is a restriction per NodeId, enforce it along with the allow/deny lists
        // TODO: Implement in the update
        // self.packets_received.insert((src.clone(), packet.clone()));

        true
    }
}
