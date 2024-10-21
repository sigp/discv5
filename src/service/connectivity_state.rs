//! This keeps track of our whether we should advertise an external IP address or not based on
//! whether we think we are externally contactable or not.
//!
//! We determine this by advertising our discovered IP address, if we receive inbound connections,
//! then we know we are externally contactable. If we see nothing for a period of time, we consider
//! ourselves non-contactable and revoke our advertised IP address. We wait for
//! DURATION_UNTIL_NEXT_CONNECTIVITY_ATTEMPT before trying again.

use std::time::{Duration, Instant};

const DURATION_UNTIL_NEXT_CONNECTIVITY_ATTEMPT: Duration = Duration::from_secs(21600); // 6 hours

pub(crate) struct ConnectivityState {
    /// Whether we consider ourselves externally contactable or not.
    contactable: bool,
    /// The duration we will wait for incoming connections before deciding if we are contactable or
    /// not. If this is None, we consider ourselves always contactable.
    duration_for_incoming_connections: Option<Duration>,
    /// If we are awaiting for incoming connections, this is the instant that we stop waiting.
    ipv4_incoming_wait_time: Option<Instant>,
    /// If we are awaiting for incoming connections, this is the instant that we stop waiting.
    ipv6_incoming_wait_time: Option<Instant>,
    /// The time that we being checking connectivity tests for ipv4.
    ipv4_next_connectivity_test: Instant,
    /// The time that we being checking connectivity tests for ipv6.
    ipv6_next_connectivity_test: Instant,
}

impl ConnectivityState {
    pub fn new(duration_for_incoming_connections: Option<Duration>) -> Self {
        ConnectivityState {
            contactable: false,
            duration_for_incoming_connections,
            ipv4_incoming_wait_time: None,
            ipv6_incoming_wait_time: None,
            ipv4_next_connectivity_test: Instant::now(),
            ipv6_next_connectivity_test: Instant::now(),
        }
    }
}
