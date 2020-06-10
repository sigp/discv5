use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The time window that the size of the cache is enforced for. I.e if the size 5 and
/// ENFORCED_SIZE_TIME is 1, this will allow 5 entries per second. This MUST be less than the
/// `CACHE_TIME`.
pub const ENFORCED_SIZE_TIME: u64 = 1;

pub struct ReceivedPacket<T> {
    /// The source that sent us the packet.
    pub content: T,
    /// The time the packet was received.
    pub received: Instant,
}

pub struct ReceivedPacketCache<T> {
    /// The size of the cache.
    size: usize,
    /// The cache stores CACHE_TIME seconds worth of information to calculate a moving average.
    /// This variable keeps track the number of elements in the cache within the
    /// ENFORCED_SIZE_TIME.
    time_window: u64,
    within_enforced_time: usize,
    /// The underlying data structure.
    inner: VecDeque<ReceivedPacket<T>>,
}

impl<T> ReceivedPacketCache<T> {
    /// Creates a new `ReceivedPacketCache` with a specified size from which no more can enter.
    pub fn new(size: usize, time_window: u64) -> Self {
        Self {
            size,
            time_window,
            within_enforced_time: 0,
            inner: VecDeque::with_capacity(size),
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

    pub fn insert_reset(&mut self, content: T) -> bool {
        self.reset();
        self.insert(content)
    }

    pub fn insert(&mut self, content: T) -> bool {
        if self.within_enforced_time >= self.size {
            // The cache is full
            return false;
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
