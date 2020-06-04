//! A filter which decides whether to accept/reject incoming UDP packets.

use crate::packet::Packet;
use enr::NodeId;
use std::collections::HashMap;
use std::net::SocketAddr;

mod cache;
mod config;

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
    packets_received: ReceivedPacketCache<(SocketAddr, NodeId)>,

    /// The list of waiting responses. These are used to allow incoming packets from sources
    /// that we are expected a response from bypassing the rate-limit filters.
    awaiting_responses: HashMap<SocketAddr, usize>,
}

impl Filter {
    pub fn new(config: FilterConfig) -> Filter {
        Filter {
            config,
            raw_packets_received: ReceivedPacketCache::new(config.max_requests_per_second),
            packets_received: ReceivedPacketCache::new(config.max_requests_per_second),
            awaiting_responses: HashMap::new(),
        }
    }

    /// The first check. This determines if a new UDP packet should be decoded or dropped.
    pub fn initial_pass(&mut self, src: &SocketAddr) -> bool {
        // TODO: Add to the rate limit. Check rate limits, white and black listed addresses etc.
        true
    }

    pub fn final_pass(&mut self, src: &SocketAddr, packet: &Packet) -> bool {
        // TODO: Check the Node Id, see if it passes packet-level filtering
        true
    }
}
