use hashlink::LinkedHashMap;
use std::{
    hash::Hash,
    time::{Duration, Instant},
};

pub struct LruTimeCache<K, V> {
    /// The main map storing the internal values. It stores the time the value was inserted and an
    /// optional tag to keep track of individual values.
    map: LinkedHashMap<K, (V, Instant, bool)>,
    /// The time elements remain in the cache.
    ttl: Duration,
    /// The max size of the cache.
    capacity: usize,
    /// Optional count of specific tagged elements. This is used in discv5 for tracking
    /// the number of unreachable sessions currently held.
    tagged_count: usize,
}

impl<K: Clone + Eq + Hash, V> LruTimeCache<K, V> {
    pub fn new(ttl: Duration, capacity: Option<usize>) -> LruTimeCache<K, V> {
        let capacity = if let Some(cap) = capacity {
            cap
        } else {
            usize::MAX
        };
        LruTimeCache {
            map: LinkedHashMap::new(),
            ttl,
            capacity,
            tagged_count: 0,
        }
    }

    /// Returns the number of elements that are currently tagged in the cache.
    pub fn tagged(&self) -> usize {
        self.tagged_count
    }

    // Insert an untagged key-value pair into the cache.
    pub fn insert(&mut self, key: K, value: V) {
        self.insert_raw(key, value, false);
    }

    // Insert a tagged key-value pair into the cache.
    #[cfg(test)]
    pub fn insert_tagged(&mut self, key: K, value: V) {
        self.insert_raw(key, value, true);
    }

    /// Inserts a key-value pair into the cache.
    pub fn insert_raw(&mut self, key: K, value: V, tagged: bool) {
        let now = Instant::now();
        if let Some(old_value) = self.map.insert(key, (value, now, tagged)) {
            // If the old value was tagged but the new one isn't, we reduce our count
            if !tagged && old_value.2 {
                self.tagged_count = self.tagged_count.saturating_sub(1);
            } else if tagged && !old_value.2 {
                // Else if the new value is tagged and the old wasn't tagged increment the count
                self.tagged_count += 1;
            }
        } else if tagged {
            // No previous value, increment the tagged count
            self.tagged_count += 1;
        }

        if self.map.len() > self.capacity {
            if let Some((_, value)) = self.map.pop_front() {
                if value.2 {
                    // We have removed a tagged element
                    self.tagged_count = self.tagged_count.saturating_sub(1);
                }
            }
        }
    }

    /// Retrieves a reference to the value stored under `key`, or `None` if the key doesn't exist.
    /// Also removes expired elements and updates the time.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.get_mut(key).map(|value| &*value)
    }

    /// Retrieves a mutable reference to the value stored under `key`, or `None` if the key doesn't exist.
    /// Also removes expired elements and updates the time.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let now = Instant::now();
        self.remove_expired_values(now);

        match self.map.raw_entry_mut().from_key(key) {
            hashlink::linked_hash_map::RawEntryMut::Occupied(mut occupied) => {
                occupied.get_mut().1 = now;
                occupied.to_back();
                Some(&mut occupied.into_mut().0)
            }
            hashlink::linked_hash_map::RawEntryMut::Vacant(_) => None,
        }
    }

    /// Returns a reference to the value with the given `key`, if present and not expired, without
    /// updating the timestamp.
    pub fn peek(&self, key: &K) -> Option<&V> {
        if let Some((value, time, _)) = self.map.get(key) {
            return if *time + self.ttl >= Instant::now() {
                Some(value)
            } else {
                None
            };
        }
        None
    }

    /// Returns the size of the cache, i.e. the number of cached non-expired key-value pairs.
    pub fn len(&mut self) -> usize {
        self.remove_expired_values(Instant::now());
        self.map.len()
    }

    /// Removes a key-value pair from the cache, returning the value at the key if the key
    /// was previously in the map.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.map.remove(key)?;

        // This element was tagged, reduce the count
        if value.2 {
            self.tagged_count = self.tagged_count.saturating_sub(1);
        }
        Some(value.0)
    }

    /// Removes expired items from the cache.
    fn remove_expired_values(&mut self, now: Instant) {
        let mut expired_keys = vec![];

        for (key, (_, time, _)) in self.map.iter_mut() {
            if *time + self.ttl >= now {
                break;
            }
            expired_keys.push(key.clone());
        }

        for k in expired_keys {
            if let Some(v) = self.map.remove(&k) {
                // This key was tagged, reduce the count
                if v.2 {
                    self.tagged_count = self.tagged_count.saturating_sub(1);
                }
            }
        }
    }

    pub fn clear(&mut self) {
        self.map.clear()
    }
}

#[cfg(test)]
mod tests {
    use crate::lru_time_cache::LruTimeCache;
    use std::time::Duration;

    #[test]
    fn insert() {
        let mut cache = LruTimeCache::new(Duration::from_secs(10), None);

        cache.insert(1, 10);
        cache.insert(2, 20);
        cache.insert(3, 30);

        assert_eq!(Some(&10), cache.get(&1));
        assert_eq!(Some(&20), cache.get(&2));
        assert_eq!(Some(&30), cache.get(&3));
    }

    #[test]
    fn capacity() {
        let mut cache = LruTimeCache::new(Duration::from_secs(10), Some(2));

        cache.insert(1, 10);
        cache.insert(2, 20);
        assert_eq!(2, cache.len());

        cache.insert(3, 30);
        assert_eq!(2, cache.len());
        assert_eq!(Some(&20), cache.get(&2));
        assert_eq!(Some(&30), cache.get(&3));
    }

    #[test]
    fn tagging() {
        let mut cache = LruTimeCache::new(Duration::from_secs(10), Some(2));

        cache.insert_tagged(1, 10);
        cache.insert(2, 20);
        assert_eq!(2, cache.len());
        assert_eq!(1, cache.tagged());

        cache.insert_tagged(3, 30);
        assert_eq!(2, cache.len());
        assert_eq!(1, cache.tagged());
        assert_eq!(Some(&20), cache.get(&2));
        assert_eq!(Some(&30), cache.get(&3));

        cache.insert_tagged(2, 30);
        assert_eq!(2, cache.tagged());

        cache.insert(4, 30);
        assert_eq!(1, cache.tagged());
        cache.insert(5, 30);
        assert_eq!(0, cache.tagged());
    }

    #[test]
    fn get() {
        let mut cache = LruTimeCache::new(Duration::from_secs(10), Some(2));

        cache.insert(1, 10);
        cache.insert(2, 20);
        assert_eq!(Some(&10), cache.get(&1));

        cache.insert(3, 30);
        // `1` is alive as `get()` updates the timestamp.
        assert_eq!(Some(&10), cache.get(&1));
        // `2` is removed as `2` is oldest at the time `3` was inserted.
        assert_eq!(None, cache.get(&2));
    }

    #[test]
    fn get_mut() {
        let mut cache = LruTimeCache::new(Duration::from_secs(10), None);

        cache.insert(1, 10);
        let v = cache.get_mut(&1).expect("should have value");
        *v = 100;

        assert_eq!(Some(&100), cache.get(&1));
    }

    #[test]
    fn peek() {
        let mut cache = LruTimeCache::new(Duration::from_secs(10), Some(2));

        cache.insert(1, 10);
        cache.insert(2, 20);
        assert_eq!(Some(&10), cache.peek(&1));

        cache.insert(3, 30);
        // `1` is removed as `peek()` does not update the time.
        assert_eq!(None, cache.peek(&1));
        assert_eq!(Some(&20), cache.get(&2));
    }

    #[test]
    fn len() {
        let mut cache = LruTimeCache::new(Duration::from_secs(10), None);

        assert_eq!(0, cache.len());

        cache.insert(1, 10);
        cache.insert(2, 20);
        cache.insert(3, 30);
        assert_eq!(3, cache.len());
    }

    #[test]
    fn remove() {
        let mut cache = LruTimeCache::new(Duration::from_secs(10), None);

        cache.insert(1, 10);
        assert_eq!(Some(10), cache.remove(&1));
        assert_eq!(None, cache.get(&1));
        assert_eq!(None, cache.remove(&1));
    }

    mod ttl {
        use crate::lru_time_cache::LruTimeCache;
        use std::{thread::sleep, time::Duration};

        const TTL: Duration = Duration::from_millis(100);

        #[test]
        fn get() {
            let mut cache = LruTimeCache::new(TTL, None);
            cache.insert(1, 10);
            assert_eq!(Some(&10), cache.get(&1));

            sleep(TTL);
            assert_eq!(None, cache.get(&1));
        }

        #[test]
        fn peek() {
            let mut cache = LruTimeCache::new(TTL, None);
            cache.insert(1, 10);
            assert_eq!(Some(&10), cache.peek(&1));

            sleep(TTL);
            assert_eq!(None, cache.peek(&1));
        }

        #[test]
        fn len() {
            let mut cache = LruTimeCache::new(TTL, None);
            cache.insert(1, 10);
            assert_eq!(1, cache.len());

            sleep(TTL);
            assert_eq!(0, cache.len());
        }

        #[test]
        fn ttl() {
            let mut cache = LruTimeCache::new(TTL, None);
            cache.insert(1, 10);
            sleep(TTL / 4);
            cache.insert(2, 20);
            sleep(TTL / 4);
            cache.insert(3, 30);
            sleep(TTL / 4);
            cache.insert(4, 40);
            sleep(TTL / 4);

            assert_eq!(3, cache.len());
            assert_eq!(None, cache.get(&1));
            assert_eq!(Some(&20), cache.get(&2));
            assert_eq!(Some(&30), cache.get(&3));
            assert_eq!(Some(&40), cache.get(&4));
        }
    }
}
