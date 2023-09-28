use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use parking_lot::RwLock;

lazy_static! {
    pub static ref METRICS: InternalMetrics = InternalMetrics::default();
}

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
        if let Some(curr_count) = self.errors.read().get(error) {
            let curr_count = curr_count.load(Ordering::Relaxed);
            self.errors
                .write()
                .get_mut(error)
                .unwrap()
                .store(curr_count.saturating_add(1), Ordering::Relaxed);
        } else {
            self.errors.write().insert(error, 0.into());
        }
    }

    pub fn as_raw(&self) -> HashMap<&'static str, usize> {
        self.errors
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
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
