/// The cache size for establishing new sessions.
pub const EST_SESSION_CACHE_SIZE: usize = 100;
/// The number of seconds to maintain an establishing session.
pub const EST_SESSION_CACHE_TTL: usize = 30;

use super::Session;
use lruc_time_cache::LruCache;

/// A collections of sessions split into a two different caches.
///
/// Newly attempted connections will do not substract from the cache size of established
/// sessions. These sessions have different ttls.
pub struct Sessions {
    /// Sessions that are attempted to be negotiated.
    establishing_sessions: LruCache<EstablishingSession>,
    /// Sessions that are established
    established_sessions: LruCache<Session>,
}

impl Sessions {
    pub fn new(
        establishing_ttl: Duration,
        established_ttl: Duration,
        established_size: usize,
    ) -> Self {
        Sessions {
            establishing_sessions: LruCache::with_expiry_duration_and_capacity(
                std::time::Duration::from_secs(EST_SESSION_CACHE_TTL),
                EST_SESSION_CACHE_SIZE,
            ),
            established_sessions: LruCache::with_expiry_duration_and_capacity(
                established_ttl,
                established_size,
            ),
        }
    }
}
