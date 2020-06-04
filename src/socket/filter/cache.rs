use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct ReceivedPacket<T> {
    /// The source that sent us the packet.
    pub content: T,
    /// The time the packet was received.
    pub received: Instant,
}

pub struct ReceivedPacketCache<T> {
    /// The number of seconds to
    size: usize,
    inner: VecDeque<ReceivedPacket<T>>,
}

impl<T> ReceivedPacketCache<T> {
    /// Creates a new `ReceivedPacketCache` with a specified size from which no more can enter.
    pub fn new(size: usize) -> Self {
        Self {
            size,
            inner: VecDeque::with_capacity(size),
        }
    }

    /// Remove expired packets. We only keep, one second of data in the cache.
    pub fn reset(&mut self) {
        let now = Instant::now();

        while let Some(packet) = self.inner.pop_front() {
            if packet.received > Instant::now() - Duration::from_secs(1) {
                // add the packet back and end
                self.inner.push_front(packet);
                break;
            }
        }
    }

    pub fn insert(&mut self, content: T) -> bool {
        self.reset();
        if self.inner.len() >= self.size {
            // The cache is full
            return false;
        } else {
            let received_packet = ReceivedPacket {
                content,
                received: Instant::now(),
            };
            self.inner.push_back(received_packet);
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
