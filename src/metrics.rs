use enr::NodeId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

lazy_static! {
    pub static ref METRICS: InternalMetrics = InternalMetrics::new();
}

pub struct InternalMetrics {
    pub active_sessions: AtomicUsize,
    pub moving_window: u64,
    pub unsolicited_requests_per_second: AtomicUsize,
    pub requests_per_node_per_second: RwLock<HashMap<NodeId, f64>>,
    pub requests_per_ip_per_second: RwLock<HashMap<IpAddr, f64>>,
}

impl InternalMetrics {
    pub fn new() -> Self {
        InternalMetrics {
            moving_window: 5,
            active_sessions: AtomicUsize::new(0),
            unsolicited_requests_per_second: AtomicUsize::new(0),
            requests_per_node_per_second: RwLock::new(HashMap::new()),
            requests_per_ip_per_second: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Metrics {
    pub active_sessions: usize,
    pub unsolicited_requests_per_second: f64,
    pub requests_per_node_per_second: HashMap<NodeId, f64>,
    pub requests_per_ip_per_second: HashMap<IpAddr, f64>,
}

impl From<&METRICS> for Metrics {
    fn from(internal_metrics: &METRICS) -> Self {
        Metrics {
            active_sessions: internal_metrics.active_sessions.load(Ordering::Relaxed),
            unsolicited_requests_per_second: internal_metrics
                .unsolicited_requests_per_second
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
