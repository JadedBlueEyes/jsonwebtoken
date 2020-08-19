use std::cmp::Eq;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Instant, Duration};

// use cached::Cached;

use std::collections::hash_map::Entry;

enum Status {
    NotFound,
    Found,
    Expired,
}

/// Cache store bound by time
///
/// Values are timestamped when inserted and are
/// evicted if expired at time of retrieval.
///
/// Note: This cache is in-memory only
#[derive(Clone, Debug)]
pub struct ExpiringCache<K, V> {
    store: HashMap<K, (Instant, Duration, V)>,
    default_lifespan: Duration,
    hits: u64,
    misses: u64,
    initial_capacity: Option<usize>,
}

#[allow(dead_code)]
impl<K: Hash + Eq, V> ExpiringCache<K, V> {
    /// Creates a new `ExpiringCache` with a specified default lifespan
    pub fn with_lifespan(duration: Duration) -> ExpiringCache<K, V> {
        ExpiringCache {
            store: Self::new_store(None),
            default_lifespan: duration,
            hits: 0,
            misses: 0,
            initial_capacity: None,
        }
    }

    /// Creates a new `ExpiringCache` with a specified default lifespan and
    /// cache-store with the specified pre-allocated capacity
    pub fn with_lifespan_and_capacity(duration: Duration, size: usize) -> ExpiringCache<K, V> {
        ExpiringCache {
            store: Self::new_store(Some(size)),
            default_lifespan: duration,
            hits: 0,
            misses: 0,
            initial_capacity: Some(size),
        }
    }

    fn new_store(capacity: Option<usize>) -> HashMap<K, (Instant, Duration, V)> {
        capacity.map_or_else(HashMap::new, HashMap::with_capacity)
    }

    // -- Trait after this point --

    pub fn cache_get(&mut self, key: &K) -> Option<&V> {
        let status = {
            let val = self.store.get(key);
            if let Some(&(instant, duration, _)) = val {
                if instant.elapsed() < duration {
                    Status::Found
                } else {
                    Status::Expired
                }
            } else {
                Status::NotFound
            }
        };
        match status {
            Status::NotFound => {
                self.misses += 1;
                None
            }
            Status::Found => {
                self.hits += 1;
                self.store.get(key).map(|stamped| &stamped.2)
            }
            Status::Expired => {
                self.misses += 1;
                self.store.remove(key).unwrap();
                None
            }
        }
    }

    fn cache_get_mut(&mut self, key: &K) -> Option<&mut V> {
        let status = {
            let val = self.store.get(key);
            if let Some(&(instant, duration, _)) = val {
                if instant.elapsed() < duration {
                    Status::Found
                } else {
                    Status::Expired
                }
            } else {
                Status::NotFound
            }
        };
        match status {
            Status::NotFound => {
                self.misses += 1;
                None
            }
            Status::Found => {
                self.hits += 1;
                self.store.get_mut(key).map(|stamped| &mut stamped.2)
            }
            Status::Expired => {
                self.misses += 1;
                self.store.remove(key).unwrap();
                None
            }
        }
    }

    fn cache_get_or_set_with<F: FnOnce() -> V>(&mut self, key: K, f: F) -> &mut V {
        match self.store.entry(key) {
            Entry::Occupied(mut occupied) => {
                let o = occupied.get();
                if o.0.elapsed() < o.1 {
                    self.hits += 1;
                } else {
                    self.misses += 1;
                    let val = f();
                    occupied.insert((Instant::now(), self.default_lifespan, val));
                }
                &mut occupied.into_mut().2
            }
            Entry::Vacant(vacant) => {
                self.misses += 1;
                let val = f();
                &mut vacant.insert((Instant::now(), self.default_lifespan, val)).2
            }
        }
    }

    fn cache_set(&mut self, key: K, val: V) -> Option<V> {
        let stamped = (Instant::now(), self.default_lifespan, val);
        self.store.insert(key, stamped).map(|(_, _, v)| v)
    }

    pub fn cache_set_with_lifespan(&mut self, key: K, lifetime: Duration, val: V) -> Option<V> {
        let stamped = (Instant::now(), lifetime, val);
        self.store.insert(key, stamped).map(|(_, _, v)| v)
    }

    fn cache_remove(&mut self, k: &K) -> Option<V> {
        self.store.remove(k).map(|(_, _, v)| v)
    }
    fn cache_clear(&mut self) {
        self.store.clear();
    }
    fn cache_reset(&mut self) {
        self.store = Self::new_store(self.initial_capacity);
    }
    fn cache_size(&self) -> usize {
        self.store.len()
    }
    fn cache_hits(&self) -> Option<u64> {
        Some(self.hits)
    }
    fn cache_misses(&self) -> Option<u64> {
        Some(self.misses)
    }
    fn cache_lifespan(&self) -> Option<Duration> {
        Some(self.default_lifespan)
    }

    fn cache_set_lifespan(&mut self, duration: Duration) -> Option<Duration> {
        let old = self.default_lifespan;
        self.default_lifespan = duration;
        Some(old)
    }
}

#[cfg(test)]
/// Cache store tests
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::ExpiringCache;

    const INIT_CAPACITY: usize = 15;

    #[test]
    fn timed_cache() {
        let mut c = ExpiringCache::with_lifespan(Duration::from_secs(2));
        assert!(c.cache_get(&1).is_none());
        let misses = c.cache_misses().unwrap();
        assert_eq!(1, misses);

        assert_eq!(c.cache_set(1, 100), None);
        assert!(c.cache_get(&1).is_some());
        let hits = c.cache_hits().unwrap();
        let misses = c.cache_misses().unwrap();
        assert_eq!(1, hits);
        assert_eq!(1, misses);

        sleep(Duration::new(2, 0));
        assert!(c.cache_get(&1).is_none());
        let misses = c.cache_misses().unwrap();
        assert_eq!(2, misses);

        let old = c.cache_set_lifespan(Duration::from_secs(1)).unwrap();
        assert_eq!(Duration::from_secs(2), old);
        assert_eq!(c.cache_set(1, 100), None);
        assert!(c.cache_get(&1).is_some());
        let hits = c.cache_hits().unwrap();
        let misses = c.cache_misses().unwrap();
        assert_eq!(2, hits);
        assert_eq!(2, misses);

        sleep(Duration::new(1, 0));
        assert!(c.cache_get(&1).is_none());
        let misses = c.cache_misses().unwrap();
        assert_eq!(3, misses);
    }

    #[test]
    fn clear() {
        let mut c = ExpiringCache::with_lifespan(Duration::from_secs(3600));

        assert_eq!(c.cache_set(1, 100), None);
        assert_eq!(c.cache_set(2, 200), None);
        assert_eq!(c.cache_set(3, 300), None);
        c.cache_clear();

        assert_eq!(0, c.cache_size());
    }

    #[test]
    fn reset() {
        let mut c = ExpiringCache::with_lifespan(Duration::from_secs(100));
        assert_eq!(c.cache_set(1, 100), None);
        assert_eq!(c.cache_set(2, 200), None);
        assert_eq!(c.cache_set(3, 300), None);
        assert_eq!(3, c.store.capacity());

        c.cache_reset();

        assert_eq!(0, c.store.capacity());

        let mut c = ExpiringCache::with_lifespan_and_capacity(Duration::from_secs(100), INIT_CAPACITY);
        assert_eq!(c.cache_set(1, 100), None);
        assert_eq!(c.cache_set(2, 200), None);
        assert_eq!(c.cache_set(3, 300), None);
        // assert!(init_capacity >= c.store.capacity());

        c.cache_reset();

        // assert_eq!(init_capacity, c.store.capacity());
    }

    #[test]
    fn remove() {
        let mut c = ExpiringCache::with_lifespan(Duration::from_secs(3600));

        assert_eq!(c.cache_set(1, 100), None);
        assert_eq!(c.cache_set(2, 200), None);
        assert_eq!(c.cache_set(3, 300), None);

        assert_eq!(Some(100), c.cache_remove(&1));
        assert_eq!(2, c.cache_size());
    }

    #[test]
    fn get_or_set_with() {
        let mut c = ExpiringCache::with_lifespan(Duration::from_secs(2));

        assert_eq!(c.cache_get_or_set_with(0, || 0), &0);
        assert_eq!(c.cache_get_or_set_with(1, || 1), &1);
        assert_eq!(c.cache_get_or_set_with(2, || 2), &2);
        assert_eq!(c.cache_get_or_set_with(3, || 3), &3);
        assert_eq!(c.cache_get_or_set_with(4, || 4), &4);
        assert_eq!(c.cache_get_or_set_with(5, || 5), &5);

        assert_eq!(c.cache_misses(), Some(6));

        assert_eq!(c.cache_get_or_set_with(0, || 0), &0);

        assert_eq!(c.cache_misses(), Some(6));

        assert_eq!(c.cache_get_or_set_with(0, || 42), &0);

        assert_eq!(c.cache_misses(), Some(6));

        sleep(Duration::new(2, 0));

        assert_eq!(c.cache_get_or_set_with(1, || 42), &42);

        assert_eq!(c.cache_misses(), Some(7));
    }
}