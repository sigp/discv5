//! A filter which decides whether to accept/reject incoming UDP packets.

use crate::packet::Packet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

mod cache;
mod config;

use crate::discv5::PERMIT_BAN_LIST;
use crate::metrics::METRICS;
use cache::ReceivedPacketCache;
pub use config::FilterConfig;

/// The packet filter which decides whether we accept or reject incoming packets.
pub(crate) struct Filter {
    /// Configuration for the packet filter.
    config: FilterConfig,

    /// An ordered (by time) collection of recently seen packets by SocketAddr. The packet data is not
    /// stored here..
    raw_packets_received: ReceivedPacketCache<SocketAddr>,

    /// An ordered (by time) collection of seen packets that have passed the first filter check and
    /// have an associated NodeId.
    _packets_received: ReceivedPacketCache<(SocketAddr, Packet)>,
}

impl Filter {
    pub fn new(config: &FilterConfig) -> Filter {
        Filter {
            config: config.clone(),
            raw_packets_received: ReceivedPacketCache::new(config.max_requests_per_second),
            _packets_received: ReceivedPacketCache::new(config.max_requests_per_second),
        }
    }

    /// The first check. This determines if a new UDP packet should be decoded or dropped.
    pub fn initial_pass(&mut self, src: &SocketAddr) -> bool {
        if PERMIT_BAN_LIST.read().permit_ips.get(&src.ip()).is_some() {
            return true;
        }

        if PERMIT_BAN_LIST.read().ban_ips.get(&src.ip()).is_some() {
            return false;
        }

        // update the cache
        self.raw_packets_received.reset();

        // if there is a restriction per IP, enforce it
        if let Some(max_requests_per_ip_per_second) = self.config.max_requests_per_ip_per_second {
            if self
                .raw_packets_received
                .iter()
                .filter(|past_src| past_src.content.ip() == src.ip())
                .count()
                >= max_requests_per_ip_per_second
            {
                return false;
            }
        }

        // Add the un-solicited request to the cache
        // If this is over the maximum requests per second, it will be rejected and return false.
        let result = self.raw_packets_received.insert(src.clone());

        result
    }

    pub fn final_pass(&mut self, _src: &SocketAddr, _packet: &Packet) -> bool {
        // let allow_deny_list = self.allow_deny_list.read();

        // if there is a restriction per NodeId, enforce it along with the allow/deny lists
        // TODO: Implement in the update
        // self.packets_received.insert((src.clone(), packet.clone()));

        true
    }
}
