//! This provides a cache to check rate limits as well as store data for metrics.
//!
//! The cache essentially consists of a time-ordered list of elements. The list is split into two
//! sections, within the enforced time and without.
//!
//!                
//! |               | Enforced Time |  
//! \[x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x\]
//!                 
//! The enforced time represents one seconds worth of elements. The target aims to limit the
//! number of elements that can be inserted within the enforced time. The length of the list is
//! determined by the `time_window` this can be longer than one second and can be used by metrics
//! to average results over large values than one second.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// The time window that the size of the cache is enforced for. I.e if the size is 5 and
/// ENFORCED_SIZE_TIME is 1 second, this will allow 5 entries per second. This MUST be less than the
/// cache's `time_window`.
pub const ENFORCED_SIZE_TIME: u64 = 1;

pub struct ReceivedPacket<T> {
    /// The source that sent us the packet.
    pub content: T,
    /// The time the packet was received.
    pub received: Instant,
}

pub struct ReceivedPacketCache<T> {
    /// The target number of entries per ENFORCED_SIZE_TIME before inserting new elements reports
    /// failure. The maximum size of the cache is target*time_window
    target: usize,
    /// The cache stores `time_window` seconds worth of information to calculate a moving average.
    /// This variable keeps track the number of elements in the cache within the
    /// ENFORCED_SIZE_TIME.
    time_window: u64,
    /// This stores the current number of messages that are within the `ENFORCED_SIZE_TIME`.
    within_enforced_time: usize,
    /// The underlying data structure.
    inner: VecDeque<ReceivedPacket<T>>,
}

impl<T> ReceivedPacketCache<T> {
    /// Creates a new `ReceivedPacketCache` with a specified size from which no more can enter.
    pub fn new(target: usize, time_window: u64) -> Self {
        Self {
            target,
            time_window,
            within_enforced_time: 0,
            inner: VecDeque::with_capacity(target * time_window as usize),
        }
    }

    /// Remove expired packets. We only keep, `CACHE_TIME` of data in the cache.
    pub fn reset(&mut self) {
        while let Some(packet) = self.inner.pop_front() {
            if packet.received > Instant::now() - Duration::from_secs(self.time_window) {
                // add the packet back and end
                self.inner.push_front(packet);
                break;
            }
        }
        // update the within_enforced_time
        let mut count = 0;
        for packet in self.inner.iter().rev() {
            if packet.received > Instant::now() - Duration::from_secs(ENFORCED_SIZE_TIME) {
                count += 1;
            } else {
                break;
            }
        }
        self.within_enforced_time = count;
    }

    /// Inserts an element into the cache, removing any expired elements.
    pub fn cache_insert(&mut self, content: T) -> bool {
        self.reset();
        self.internal_insert(content)
    }

    /// Inserts an element into the cache without removing expired elements.
    fn internal_insert(&mut self, content: T) -> bool {
        if self.within_enforced_time >= self.target {
            // Reached the target
            false
        } else {
            let received_packet = ReceivedPacket {
                content,
                received: Instant::now(),
            };
            self.inner.push_back(received_packet);
            self.within_enforced_time += 1;
            true
        }
    }
}

impl<T> std::ops::Deref for ReceivedPacketCache<T> {
    type Target = VecDeque<ReceivedPacket<T>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for ReceivedPacketCache<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
