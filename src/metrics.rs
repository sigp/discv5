use std::sync::atomic::{AtomicUsize, Ordering};

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
    /// The number of bytes sent.
    pub bytes_sent: AtomicUsize,
    /// The number of bytes received.
    pub bytes_recv: AtomicUsize,
}

impl Default for InternalMetrics {
    fn default() -> Self {
        InternalMetrics {
            moving_window: 5,
            active_sessions: AtomicUsize::new(0),
            unsolicited_requests_per_window: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            bytes_recv: AtomicUsize::new(0),
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
        }
    }
}
