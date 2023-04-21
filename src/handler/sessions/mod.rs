use crate::{lru_time_cache::LruTimeCache, node_info::NodeAddress};
use std::time::Duration;

mod crypto;
mod limiter;
mod session;

use limiter::SessionLimiter;
pub use session::Session;

pub struct Sessions {
    pub cache: LruTimeCache<NodeAddress, Session>,
    limiter: Option<SessionLimiter>,
}

impl Sessions {
    pub fn new(
        cache_capacity: usize,
        entry_ttl: Duration,
        unreachable_enr_limit: Option<usize>,
    ) -> Self {
        let (tx, rx) = futures::channel::mpsc::channel::<NodeAddress>(cache_capacity);
        let sessions = LruTimeCache::new(entry_ttl, Some(cache_capacity), Some(tx));
        let limiter = unreachable_enr_limit.map(|limit| SessionLimiter::new(rx, limit));
        Sessions {
            cache: sessions,
            limiter,
        }
    }
}
