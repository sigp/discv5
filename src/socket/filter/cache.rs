pub struct ReceivedPacket<T> {
    /// The source that sent us the packet.
    pub contents: T,
    /// The time the packet was received.
    pub received: Instant,
}

struct ReceivedPacketCache<T> {
    /// The number of seconds to 
    size: usize
    inner: VecDeque<ReceivedPacket<T>>
}

impl<T> ReceivedPacketCache<T> {

    /// Creates a new `ReceivedPacketCache` with a specified size in seconds to retain.
    pub fn new(size: usize) -> Self {
        Self {
            size: Duration::from_secs(size),
            inner: VecDeque::with_capacity(100)
        }
    }

    /// Remove expired packets. We only keep, `size` seconds in the cache.
    pub fn reset(&mut self) {
        let now = Instant::now();

        while let Some(packet) = self.inner.pop_front() {
            if packet.received > Instant::now() - self.size {
                // add the packet back and end
                self.inner.push_front(packet);
                break;
            }
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
    type Target = VecDeque<ReceivedPacket<T>>;

    fn deref_mut(&self) -> &Self::Target {
        &mut self.inner
    }
}
