//! A custom data structure for storing pending requests and managing their timeouts.
//!
//! A delay queue is used to keep track of when requests are expired and `Stream` is implemented on
//! `TimedRequests` which provides expired requests when polled.

use crate::session_service::Request;
use futures::{Async, Poll, Stream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_timer::{delay_queue, DelayQueue};

/// A collection of requests that have an associated timeout.
pub struct TimedRequests {
    /// Pending raw requests with timeout keys for removing from a delay queue and to be identified during a timeout.
    /// These are indexed by SocketAddr as WHOAREYOU messages do not return a source node id to
    /// match against.
    requests: HashMap<SocketAddr, Vec<RequestTimeout>>,

    /// A queue indicating when a request has timed out.
    timeouts: DelayQueue<TimeoutIndex>,

    ///  A unique key to identify stored requests for timeout matching.
    current_key: RequestKey,

    /// The duration of each request before timing out.
    request_timeout: Duration,
}

/// Unique key for matching requests on timeout. This is a sequential `usize` identifier.
#[derive(Debug, Clone, Copy, PartialEq)]
struct RequestKey(usize);

impl RequestKey {
    pub fn new() -> Self {
        RequestKey(0)
    }

    pub fn next(&self) -> RequestKey {
        RequestKey(self.0.saturating_add(1))
    }
}

/// Indexes pending requests for timeouts.
#[derive(Debug)]
struct TimeoutIndex {
    /// The destination `SocketAddr` for pending requests hashmap lookup.
    dst: SocketAddr,
    /// A unique key to match a specific request for a socket addr.
    request_key: RequestKey,
}

impl TimeoutIndex {
    pub fn new(dst: SocketAddr, request_key: RequestKey) -> Self {
        TimeoutIndex { dst, request_key }
    }
}

/// A request with an attached delay queue key and request key. Allows for removing the delay
/// timeout when being removed and for being removed from the collection being timed out.
struct RequestTimeout {
    pub request: Request,
    pub delay_key: delay_queue::Key,
    pub request_key: RequestKey,
}

impl RequestTimeout {
    pub fn new(request: Request, delay_key: delay_queue::Key, request_key: RequestKey) -> Self {
        RequestTimeout {
            request,
            delay_key,
            request_key,
        }
    }
}

impl Default for TimedRequests {
    fn default() -> Self {
        TimedRequests::new(Duration::from_secs(5))
    }
}

impl TimedRequests {
    pub fn new(request_timeout: Duration) -> Self {
        TimedRequests {
            requests: HashMap::new(),
            timeouts: DelayQueue::new(),
            current_key: RequestKey::new(),
            request_timeout,
        }
    }

    /// Removes a request based on the given filter. Returns `Some(Request)` if the request exists,
    /// otherwise returns None.
    pub fn remove<F: FnMut(&Request) -> bool>(
        &mut self,
        src: &SocketAddr,
        mut filter: F,
    ) -> Option<Request> {
        if let Some(requests) = self.requests.get_mut(src) {
            if let Some(pos) = requests.iter().position(|r| filter(&r.request)) {
                let request_timeout = requests.remove(pos);
                // remove the timeout
                let _ = self.timeouts.remove(&request_timeout.delay_key);
                // return the request
                Some(request_timeout.request)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn insert(&mut self, dst: SocketAddr, request: Request) {
        // create a timeout for the request
        let timeout_index = TimeoutIndex::new(dst, self.current_key);
        let delay_key = self.timeouts.insert(timeout_index, self.request_timeout);
        let request_timeout = RequestTimeout::new(request, delay_key, self.current_key);
        self.requests
            .entry(dst)
            .or_insert_with(Vec::new)
            .push(request_timeout);

        self.current_key = self.current_key.next();
    }

    pub fn exists<F: FnMut(&Request) -> bool>(&self, mut filter: F) -> bool {
        self.requests
            .iter()
            .find(|(_dst, v)| v.iter().find(|req| filter(&req.request)).is_some())
            .is_some()
    }
}

impl Stream for TimedRequests {
    type Item = (SocketAddr, Request);
    type Error = &'static str;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.timeouts.poll() {
            Ok(Async::Ready(Some(timeout_index))) => {
                let timeout_index = timeout_index.into_inner();
                let dst = timeout_index.dst;

                if let Some(requests) = self.requests.get_mut(&dst) {
                    if let Some(pos) = requests
                        .iter()
                        .position(|r| r.request_key == timeout_index.request_key)
                    {
                        let request = requests.remove(pos).request;
                        return Ok(Async::Ready(Some((dst, request))));
                    }
                }
                Err("Timed out request did not exist")
            }
            Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Err("Request delay queue error"),
        }
    }
}
