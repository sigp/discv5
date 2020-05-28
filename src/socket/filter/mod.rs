//! A filter which decides whether to accept/reject incoming UDP packets.
//!
/// The packet filter which decides whether we accept or reject incoming packets.
pub(crate) struct Filter {

    /// Configuration for the packet filter.
    config: FilterConfig,

    /// An ordered (by time) collection of recently seen packets by SocketAddr. The packet data is not
    /// stored here..
    raw_packets_received: ReceivedPacketCache<SocketAddr>

    /// An ordered (by time) collection of seen packets that have passed the first filter check and
    /// have an associated NodeId. 
    packets_received: ReceivedPacketCache<(SocketAddr,NodeId>

    /// The list of waiting responses. These are used to allow incoming packets from sources
    /// that we are expected a response from bypassing the rate-limit filters.
    awaiting_responses: HashMap<SocketAddr, usize>,
}


impl Filter {
    pub fn new(config: FilterConfig) -> Filter {
        Filter {
            config,
            raw_packets_received: ReceivedPacketCache::new(),
            packets_received: ReceivedPacketCache::new(),
            awaiting_responses: HashMap::new(),
        }
    }

    /// The first check. This determines if a new UDP packet should be decoded or dropped.
    pub fn initial_pass(src: &SocketAddr) -> bool {
        // TODO: Add to the rate limit. Check rate limits, white and black listed addresses etc.
        true
    }

    pub fn final_pass(src: &SocketAddr, packet: &Packet) {
        // TODO: Check the Node Id, see if it passes packet-level filtering
        true
    }
}
