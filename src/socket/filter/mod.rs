//! A filter which decides whether to accept/reject incoming UDP packets.

use crate::packet::Packet;
//use enr::NodeId;
use std::collections::HashMap;
use std::net::SocketAddr;

mod cache;
mod config;

use cache::ReceivedPacketCache;
pub use config::FilterConfig;

/// The packet filter which decides whether we accept or reject incoming packets.
pub(crate) struct Filter {
    /// Configuration for the packet filter.
    _config: FilterConfig,

    /// An ordered (by time) collection of recently seen packets by SocketAddr. The packet data is not
    /// stored here..
    raw_packets_received: ReceivedPacketCache<SocketAddr>,

    /// An ordered (by time) collection of seen packets that have passed the first filter check and
    /// have an associated NodeId.
    packets_received: ReceivedPacketCache<(SocketAddr, Packet)>,

    /// The list of waiting responses. These are used to allow incoming packets from sources
    /// that we are expected a response from bypassing the rate-limit filters.
    _awaiting_responses: HashMap<SocketAddr, usize>,
}

impl Filter {
    pub fn new(config: &FilterConfig) -> Filter {
        Filter {
            _config: config.clone(),
            raw_packets_received: ReceivedPacketCache::new(config.max_requests_per_second),
            packets_received: ReceivedPacketCache::new(config.max_requests_per_second),
            _awaiting_responses: HashMap::new(),
        }
    }

    /// The first check. This determines if a new UDP packet should be decoded or dropped.
    pub fn initial_pass(&mut self, src: &SocketAddr) -> bool {
        // TODO: Add to the rate limit. Check rate limits, white and black listed addresses etc.
        self.raw_packets_received.insert(src.clone());
        true
    }

    pub fn final_pass(&mut self, src: &SocketAddr, packet: &Packet) -> bool {
        // TODO: Check the Node Id, see if it passes packet-level filtering
        self.packets_received.insert((src.clone(), packet.clone()));

        true
    }
}
