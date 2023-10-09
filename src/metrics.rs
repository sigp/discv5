use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use parking_lot::RwLock;

lazy_static! {
    pub static ref METRICS: InternalMetrics = InternalMetrics::default();
}

/* WARNINGS */

/// An attempt to send an empty response to a TALK message failed
pub const SEND_EMPTY_TALK_RESP_FAIL: &str = "send_empty_talk_response_failed";

/// An attempt to send a WHOAREYOU message failed
pub const SEND_WHOAREYOU_FAIL: &str = "send_whoareyou_fail";

/// An inbound RPC request timed out
pub const RPC_REQ_TIMEOUT: &str = "rpc_req_timeout";

/// An inbound RPC request errored
pub const RPC_REQ_FAIL: &str = "rpc_req_fail";

/// The results of a RPC query did not contain an ENR
pub const QUERY_RES_ENR_MISSING: &str = "query_res_enr_missing";

/// The callback used for servicing a RPC query was dropped
pub const QUERY_CALLBACK_DROPPED: &str = "query_callback_dropped";

/// No peers were close enough to satisfy the request
pub const NO_KNOWN_CLOSEST_PEERS: &str = "no_known_closest_peers";

/// The callback servicing a query failed for an unknown reason
pub const CALLBACK_FAILED: &str = "callback_failed";

/// A `NodesResponse` was received which contained too many nodes; the remainders will be ignored
pub const TRUNCATING_NODES: &str = "truncating_nodes";

/// Received the incorrect message type as a response to a request
pub const INCORRECT_RESP_TYPE: &str = "incorrect_resp_type";

/// Failed to send a response to a request
pub const SEND_RESP_FAIL: &str = "send_resp_fail";

/// A peer is advertising multiple ENRs
pub const PEER_MULTIPLE_ENRS: &str = "peer_multiple_enrs";

/// The ID of a response message didn't match the expected ID for the request message
pub const RPC_RESP_MISMATCH: &str = "rpc_resp_mismatch";

/// Failed to write to a required socket
pub const SOCK_UPDATE_FAIL: &str = "sock_update_fail";

/// Failed to respond to a FINDNODES message
pub const SEND_FINDNODES_RESP_FAIL: &str = "send_findnodes_resp_fail";

/// Responding to a NODES message failed, but was able to be partially processed (hence this is a warning)
pub const RPC_NODE_RESP_FAIL: &str = "rpc_node_resp_fail";

/// Failed to transition a node to the disconnected state
pub const NODE_UPDATE_DISCONNECT_FAIL: &str = "node_update_disconnect_fail";

/// A peer forwarded us an invalid ENR
pub const PEER_SENT_BAD_ENR: &str = "peer_sent_bad_enr";

/// An attempt to send an empty response to a FINDNODES message failed
pub const SEND_EMPTY_FINDNODES_RESP_FAIL: &str = "send_empty_findnodes_resp_fail";

/* ERRORS */

/// No request handler was found for this request
pub const NO_MATCHING_REQ_CALL: &str = "no_matching_req_call";

/// No matching nonce was found
pub const NO_MATCHING_NONCE: &str = "no_matching_nonce";

/// Failed to generate a session
pub const SESS_GENERATE_FAIL: &str = "sess_generate_fail";

/// Insertion into a kbucket did not succeed but the kbucket is not full
pub const KBUCKET_NOT_FULL: &str = "kbucket_not_full";

/// An attempt to send a packet to a peer failed due to a socket mismatch
pub const SOCK_MISMATCH_ON_SEND: &str = "sock_mismatch_on_send";

/// Failed to return from an event channel
pub const EV_CHAN_RET_FAIL: &str = "ev_chan_ret_fail";

/// An ENR advertising unreachable IP addresses was encountered (this violates the ENR invariant)
pub const UNREACHABLE_ENR: &str = "unreachable_enr";

/// A response to a message was received that was not expected
pub const RECV_RESP_UNEXPECTED: &str = "recv_resp_unexpected";

/// Represents metrics pertaining to errors and warnings that occur throughout
/// the course of server operation
#[derive(Debug, Default)]
pub struct ErrorMetrics {
    /// Total number of errors that have occurred
    pub total_errors: AtomicUsize,
    /// Total number of warnings that have occurred
    pub total_warnings: AtomicUsize,
    /// Individual errors that have occurred, with their associated counts
    pub errors: RwLock<HashMap<&'static str, AtomicUsize>>,
    /// Individual warnings that have occurred, with their associated counts
    pub warnings: RwLock<HashMap<&'static str, AtomicUsize>>,
}

impl ErrorMetrics {
    pub fn inc_total_errors(&self) {
        let current_total_errors = self.total_errors.load(Ordering::Relaxed);
        self.total_errors
            .store(current_total_errors.saturating_add(1), Ordering::Relaxed);
    }

    pub fn inc_total_warnings(&self) {
        let current_total_errors = self.total_errors.load(Ordering::Relaxed);
        self.total_errors
            .store(current_total_errors.saturating_add(1), Ordering::Relaxed);
    }

    pub fn inc_individual_error(&self, error: &'static str) {
        let lock = self.errors.read();

        let curr_count: Option<usize> = lock.get(error).map(|t| t.load(Ordering::Relaxed));

        drop(lock);

        if let Some(curr_count) = curr_count {
            self.errors
                .write()
                .get_mut(error)
                .unwrap()
                .store(curr_count.saturating_add(1), Ordering::Relaxed);
        } else {
            self.errors.write().insert(error, 0.into());
        }
    }

    pub fn inc_individual_warning(&self, warning: &'static str) {
        let lock = self.warnings.read();

        let curr_count: Option<usize> = lock.get(warning).map(|t| t.load(Ordering::Relaxed));

        drop(lock);

        if let Some(curr_count) = curr_count {
            self.warnings
                .write()
                .get_mut(warning)
                .unwrap()
                .store(curr_count.saturating_add(1), Ordering::Relaxed);
        } else {
            self.warnings.write().insert(warning, 0.into());
        }
    }

    pub fn as_raw(&self) -> HashMap<&'static str, usize> {
        self.errors
            .read()
            .iter()
            .map(|(k, v)| (*k, v.load(Ordering::Relaxed)))
            .collect()
    }
}

/// A collection of metrics used throughout the server.
pub struct InternalMetrics {
    /// The number of active UDP sessions that are currently established.
    pub active_sessions: AtomicUsize,
    /// The number of seconds to store received packets to taking a moving average over.
    pub moving_window: u64,
    /// The number of unsolicited requests received per moving window.
    pub unsolicited_requests_per_window: AtomicUsize,
    /// The number of bytes sent.
    pub bytes_sent: AtomicUsize,
    /// The number of bytes received.
    pub bytes_recv: AtomicUsize,
    /// Information about errors
    pub error_metrics: ErrorMetrics,
}

impl Default for InternalMetrics {
    fn default() -> Self {
        InternalMetrics {
            moving_window: 5,
            active_sessions: AtomicUsize::new(0),
            unsolicited_requests_per_window: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            bytes_recv: AtomicUsize::new(0),
            error_metrics: ErrorMetrics::default(),
        }
    }
}

impl InternalMetrics {
    pub fn add_recv_bytes(&self, bytes: usize) {
        let current_bytes_recv = self.bytes_recv.load(Ordering::Relaxed);
        self.bytes_recv
            .store(current_bytes_recv.saturating_add(bytes), Ordering::Relaxed);
    }

    pub fn add_sent_bytes(&self, bytes: usize) {
        let current_bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        self.bytes_sent
            .store(current_bytes_sent.saturating_add(bytes), Ordering::Relaxed);
    }

    pub fn error(&self, error: &'static str) {
        self.error_metrics.inc_total_errors();
        self.error_metrics.inc_individual_error(error);
    }

    pub fn warning(&self, warning: &'static str) {
        self.error_metrics.inc_total_warnings();
        self.error_metrics.inc_individual_warning(warning);
    }
}

#[derive(Clone, Debug)]
/// The publicly accessible metrics that can be obtained from the Discv5 server.
pub struct Metrics {
    /// The number of active UDP sessions that are currently established.
    pub active_sessions: usize,
    /// The number of unsolicited requests received per second (averaged over a moving window).
    pub unsolicited_requests_per_second: f64,
    /// The number of bytes sent.
    pub bytes_sent: usize,
    /// The number of bytes received.
    pub bytes_recv: usize,
    /// Counts of both individual and aggregate errors that have occurred
    pub errors: HashMap<&'static str, usize>,
}

impl From<&METRICS> for Metrics {
    fn from(internal_metrics: &METRICS) -> Self {
        Metrics {
            active_sessions: internal_metrics.active_sessions.load(Ordering::Relaxed),
            unsolicited_requests_per_second: internal_metrics
                .unsolicited_requests_per_window
                .load(Ordering::Relaxed) as f64
                / internal_metrics.moving_window as f64,
            bytes_sent: internal_metrics.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: internal_metrics.bytes_recv.load(Ordering::Relaxed),
            errors: internal_metrics.error_metrics.as_raw(),
        }
    }
}
