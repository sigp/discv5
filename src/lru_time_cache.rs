use hashlink::LinkedHashMap;
use std::{
    hash::Hash,
    time::{Duration, Instant},
};

pub struct LruTimeCache<K, V> {
    map: LinkedHashMap<K, (V, Instant)>,
    /// The time elements remain in the cache.
    ttl: Duration,
    /// The max size of the cache.
    capacity: usize,
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
        }
    }

    /// Inserts a key-value pair into the cache.
    pub fn insert(&mut self, key: K, value: V) {
        let now = Instant::now();
        self.map.insert(key, (value, now));

        if self.map.len() > self.capacity {
            self.map.pop_front();
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
        if let Some((value, time)) = self.map.get(key) {
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
        self.map.remove(key).map(|v| v.0)
    }

    /// Removes expired items from the cache.
    fn remove_expired_values(&mut self, now: Instant) {
        let mut expired_keys = vec![];

        for (key, (_, time)) in self.map.iter_mut() {
            if *time + self.ttl >= now {
                break;
            }
            expired_keys.push(key.clone());
        }

        for k in expired_keys {
            self.map.remove(&k);
        }
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
