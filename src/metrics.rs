use enr::NodeId;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

lazy_static! {
    pub static ref METRICS: InternalMetrics = InternalMetrics::default();
}

/// A collection of metrics used throughout the server.
pub struct InternalMetrics {
    /// The number of active UDP sessions that are currently established.
    pub active_sessions: AtomicUsize,
    /// The number of seconds to store received packets to taking a moving average over.
    pub moving_window: u64,
    /// The number of unsolicited requests received per moving window.
    pub unsolicited_requests_per_window: AtomicUsize,
    /// The number of unsolicited requests per node per second taken as a moving average over the
    /// `moving_window`.
    pub requests_per_node_per_second: RwLock<HashMap<NodeId, f64>>,
    /// The number of unsolicited requests per IP per second taken as a moving average over the
    /// `moving_window`.
    pub requests_per_ip_per_second: RwLock<HashMap<IpAddr, f64>>,
}

impl Default for InternalMetrics {
    fn default() -> Self {
        InternalMetrics {
            moving_window: 5,
            active_sessions: AtomicUsize::new(0),
            unsolicited_requests_per_window: AtomicUsize::new(0),
            requests_per_node_per_second: RwLock::new(HashMap::new()),
            requests_per_ip_per_second: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Clone, Debug)]
/// The publicly accessible metrics that can be obtained from the Discv5 server.
pub struct Metrics {
    /// The number of active UDP sessions that are currently established.
    pub active_sessions: usize,
    /// The number of unsolicited requests received per second (averaged over a moving window).
    pub unsolicited_requests_per_second: f64,
    /// The number of unsolicited requests per node per second (averaged over a moving window).
    pub requests_per_node_per_second: HashMap<NodeId, f64>,
    /// The number of unsolicited requests per IP per second (averaged over a moving window).
    pub requests_per_ip_per_second: HashMap<IpAddr, f64>,
}

impl From<&METRICS> for Metrics {
    fn from(internal_metrics: &METRICS) -> Self {
        Metrics {
            active_sessions: internal_metrics.active_sessions.load(Ordering::Relaxed),
            unsolicited_requests_per_second: internal_metrics
                .unsolicited_requests_per_window
                .load(Ordering::Relaxed) as f64
                / internal_metrics.moving_window as f64,
            requests_per_node_per_second: internal_metrics
                .requests_per_node_per_second
                .read()
                .clone(),
            requests_per_ip_per_second: internal_metrics.requests_per_ip_per_second.read().clone(),
        }
    }
}
