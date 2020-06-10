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
    pub unsolicited_requests_per_second: AtomicUsize,
    pub requests_per_node_per_second: RwLock<HashMap<NodeId, usize>>,
    pub requests_per_ip_per_second: RwLock<HashMap<IpAddr, usize>>,
}

impl InternalMetrics {
    pub fn new() -> Self {
        InternalMetrics {
            active_sessions: AtomicUsize::new(0),
            unsolicited_requests_per_second: AtomicUsize::new(0),
            requests_per_node_per_second: RwLock::new(HashMap::new()),
            requests_per_ip_per_second: RwLock::new(HashMap::new()),
        }
    }
}

pub struct Metrics {
    pub active_sessions: usize,
    pub unsolicited_requests_per_second: usize,
    pub requests_per_node_per_second: HashMap<NodeId, usize>,
    pub requests_per_ip_per_second: HashMap<IpAddr, usize>,
}

impl From<&METRICS> for Metrics {
    fn from(internal_metrics: &METRICS) -> Self {
        Metrics {
            active_sessions: internal_metrics.active_sessions.load(Ordering::Relaxed),
            unsolicited_requests_per_second: internal_metrics
                .unsolicited_requests_per_second
                .load(Ordering::Relaxed),
            requests_per_node_per_second: internal_metrics
                .requests_per_node_per_second
                .read()
                .clone(),
            requests_per_ip_per_second: internal_metrics.requests_per_ip_per_second.read().clone(),
        }
    }
}
