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
    use proptest::prelude::*;
    use rand::Rng;

    //Generates strategy for vector of keys and vector of values to use in tests
    //Range hardcoded as 1 to 1000, length passed from main test function
    prop_compose! {
    fn vec_gen(vec_length: usize)(gen_keys in prop::collection::vec(1..1000i32, vec_length))
                (gen_values in prop::collection::vec(1..1000i32,vec_length), gen_keys in Just(gen_keys)) -> (Vec<i32>, Vec<i32>) {
                    (gen_keys, gen_values)
                }
            }

    //Generates strategy for calling functions and composes a vector of integers between 1 and 4
    //Will shrink towards selecting cases that produce errors
    prop_compose! {
    fn select_gen(vec_length: usize)(gen_cases in prop::collection::vec(1..5i32, vec_length))(gen_cases in Just(gen_cases))
                ->Vec<i32>{
                    gen_cases
                }
            }

    //Main test function
    //Generates a strategy for number of operations to carry out - will shrink to minimum failing value
    //Generates large vectors of keys and values to use as dummy data
    //Selects operation to carry out based on vector of case_select integers - will shrink towards operations that cause failure
    //Maintains dummy cache in vectors to test against real cache performance
    proptest! {
        #[test]
        fn call_functions(cache_calls in 1..50u32, (test_keys, test_values) in vec_gen(100),
            case_select in select_gen(100)
            ){
            let mut cache = LruTimeCache::new(Duration::from_secs(10), Some(1000));
            //Initialising vectors to use as storage -- these are used to compare tests to real cache
            let mut test_cache_k: Vec<i32> = Vec::new();
            let mut test_cache_v: Vec<i32> = Vec::new();
            let mut test_cache_bool: Vec<bool> = Vec::new();
            //Counter for function calls loop
            let mut counter: u32 = 0;

            //Loops through case_select vector until counter reaches number of cache calls
            for (i, case) in case_select.iter().enumerate()  {
                println!("{i} , {case}");
                match case {
                    //Case one checks if the current test key is in the cache
                    //If it is, it will update value to current iteration value and tagged to true
                    //If it is not, it will add a new tagged key value pair to cache
                    1 => {
                        if test_cache_k.iter().any(|&find| find==test_keys[i]) {
                            let existing_index = test_cache_k.iter().position(|&find| find==test_keys[i]).unwrap();
                            cache.insert_tagged(test_keys[i], test_values[i]);
                            test_cache_v[existing_index] = test_values[i];
                            test_cache_bool[existing_index] = true;
                            println!("Key {} is in cache -- value now {} , tagged now true", test_keys[i], test_values[i]);
                        } else {
                        println!("Insert tagged - k {} , v {}", test_keys[i], test_values[i]);
                        cache.insert_tagged(test_keys[i], test_values[i]);
                        test_cache_k.push(test_keys[i]);
                        test_cache_v.push(test_values[i]);
                        test_cache_bool.push(true);
                        }
                    }
                    //Case two checks if the current test key is in the cache
                    //If it is, it will update value to current iteration value and tagged to false
                    //If it is not, it will add a new untagged key value pair to cache
                    2 => {
                        if test_cache_k.iter().any(|&find| find==test_keys[i]) {
                            let existing_index = test_cache_k.iter().position(|&find| find==test_keys[i]).unwrap();
                            cache.insert(test_keys[i], test_values[i]);
                            test_cache_v[existing_index] = test_values[i];
                            test_cache_bool[existing_index] = false;
                            println!("Key {} is in cache -- value now {} , tagged now true", test_keys[i], test_values[i]);
                        } else {
                        println!("Insert untagged - k {} , v {}", test_keys[i], test_values[i]);
                        cache.insert(test_keys[i], test_values[i]);
                        test_cache_k.push(test_keys[i]);
                        test_cache_v.push(test_values[i]);
                        test_cache_bool.push(false);
                        }
                    }
                    //Case three checks if there is nothing in cache
                    //If cache is empty, adds a tagged key value pair
                    //If cache has single element, removes that element
                    //If cache has multiple elements, selects one at random to remove
                    3 => {
                        if test_cache_k.len() == 0 {
                            println!("Cache empty - Insert tagged - k {} , v {}", test_keys[i], test_values[i]);
                            cache.insert_tagged(test_keys[i], test_values[i]);
                            test_cache_k.push(test_keys[i]);
                            test_cache_v.push(test_values[i]);
                            test_cache_bool.push(true);

                        } if test_cache_k.len() == 1 {
                            let rand_key: i32 = test_cache_k[0];
                            let rand_val: i32 = test_cache_v[0];
                            let rand_bool: bool = test_cache_bool[0];
                            let ret_value = cache.remove(&rand_key).unwrap();
                            test_cache_k.remove(0);
                            test_cache_v.remove(0);
                            test_cache_bool.remove(0);
                            println!("Remove - k {} , v {}, tagged {}", rand_key, rand_val, rand_bool);

                        } else {
                            let test_cache_length = test_cache_k.len();
                            let mut rand_index = rand::thread_rng().gen_range(1..test_cache_length);
                            rand_index = rand_index - 1;
                            let rand_key: i32 = test_cache_k[rand_index];
                            let rand_val: i32 = test_cache_v[rand_index];
                            let rand_bool: bool = test_cache_bool[rand_index];
                            let rem_value = cache.remove(&rand_key).unwrap();
                            test_cache_k.remove(rand_index);
                            test_cache_v.remove(rand_index);
                            test_cache_bool.remove(rand_index);
                            println!("Remove - k {} , v {} -- from cache val {}, tagged {}", rand_key, rand_val, rem_value, rand_bool);
                        }
                    }
                    //Case four checks if there is nothing in cache
                    //If cache is empty, attempts get_mut on test_key to return none
                    //If cache has single element, performs get_mut on that element
                    //If cache has multiple elements, selects one at random to get_mut
                    4 => {
                        if test_cache_k.len() == 0 {
                            println!("Cache empty - Attempt get with k {}", test_keys[i]);
                            let ret_value = cache.get_mut(&test_keys[i]);
                            if ret_value.is_none() {
                                    return Ok(());
                                }
                            let ret_value = ret_value.unwrap();
                            println!("Cache returned {}", ret_value);

                        } if test_cache_k.len() == 1 {
                            let ret_value = cache.get_mut(&test_cache_k[0]).unwrap();
                            println!("Attempt get with k {} Cache returned {} expected {}", test_cache_k[0], ret_value, test_cache_v[0]);

                        } else {
                            let test_cache_length = test_cache_k.len();
                            let mut rand_index = rand::thread_rng().gen_range(1..test_cache_length);
                            rand_index = rand_index - 1;
                            let rand_key: i32 = test_cache_k[rand_index];
                            let rand_val: i32 = test_cache_v[rand_index];
                            let ret_value = cache.get_mut(&rand_key).unwrap();
                            println!("Attempt get with k {} Cache returned {} expected {}", rand_key, ret_value, rand_val);
                        }
                    }

                    _ => {println!("Case select error");}
                }
                //Breaks loop when reaches number of cache calls specified in strategy
                counter += 1;
                if counter==cache_calls{
                    println!{"cache calls - {cache_calls}"}
                    println!{"{:?}", test_cache_k}
                    println!{"bool vec - {:?}", test_cache_bool}
                    let tagged_test_count = test_cache_bool.into_iter().filter(|b| *b).count();
                    println!{"total expected true: {} ; cache tagged true: {}", tagged_test_count, cache.tagged()}
                    //Checks that cache.tagged returns same count as true tags in test_cache_bool vector
                    assert!(tagged_test_count == cache.tagged());
                    //Checks cache.len() returns the same number of items in the cache as the test_cache vectors
                    assert!(test_cache_k.len() == cache.len());

                    break;
                }
            }

        }

    }
    
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
