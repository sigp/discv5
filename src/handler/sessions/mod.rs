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
        let (tx, limiter) = match unreachable_enr_limit {
            Some(limit) => {
                let (tx, rx) = futures::channel::mpsc::channel::<NodeAddress>(cache_capacity);
                let limiter = SessionLimiter::new(rx, limit);
                (Some(tx), Some(limiter))
            }
            None => (None, None),
        };
        let sessions = LruTimeCache::new(entry_ttl, Some(cache_capacity), tx);
        Sessions {
            cache: sessions,
            limiter,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use enr::{CombinedKey, EnrBuilder};

    #[tokio::test]
    async fn test_limiter() {
        let max_nodes_unreachable_enr = 2;
        let session_time_out = Duration::from_secs(10);
        let mut sessions = Sessions::new(3, session_time_out, Some(max_nodes_unreachable_enr));

        // first node
        let first_key = CombinedKey::generate_secp256k1();
        let mut builder = EnrBuilder::new("v4");
        let first_enr = builder.build(&first_key).unwrap();

        let first_unreachable_node = NodeAddress {
            socket_addr: "0.0.0.0:10010".parse().unwrap(),
            node_id: first_enr.node_id(),
        };
        // second node
        let second_key = CombinedKey::generate_secp256k1();
        builder = EnrBuilder::new("v4");
        let second_enr = builder.build(&second_key).unwrap();

        let second_unreachable_node = NodeAddress {
            socket_addr: "0.0.0.0:10011".parse().unwrap(),
            node_id: second_enr.node_id(),
        };
        // third node
        let third_key = CombinedKey::generate_secp256k1();
        builder = EnrBuilder::new("v4");
        let third_enr = builder.build(&third_key).unwrap();

        let third_unreachable_node = NodeAddress {
            socket_addr: "0.0.0.0:10012".parse().unwrap(),
            node_id: third_enr.node_id(),
        };
        // check if space for first node
        let res = sessions.limiter.as_mut().map(|limiter| {
            limiter.track_sessions_unreachable_enr(&first_unreachable_node, &first_enr)
        });
        res.unwrap()
            .expect("should be space for first unreachable node");
        // insert first node
        let first_session = Session::new(([0u8; 16], [0u8; 16]).into());
        sessions.cache.insert(first_unreachable_node, first_session);
        // check if space for second node
        let second_res = sessions.limiter.as_mut().map(|limiter| {
            limiter.track_sessions_unreachable_enr(&second_unreachable_node, &second_enr)
        });
        second_res
            .unwrap()
            .expect("should be space for second unreachable node");
        // insert second node
        let second_session = Session::new(([0u8; 16], [0u8; 16]).into());
        sessions
            .cache
            .insert(second_unreachable_node, second_session);

        // check if space for third node, should fail
        let third_res = sessions.limiter.as_mut().map(|limiter| {
            limiter.track_sessions_unreachable_enr(&third_unreachable_node, &third_enr)
        });
        assert!(third_res.unwrap().is_err());
        // let sessions expire
        tokio::time::sleep(session_time_out).await;
        // calling `len` removes expired entries
        sessions.cache.len();
        // retry check if space for third node, should be successful
        let third_res = sessions.limiter.as_mut().map(|limiter| {
            limiter.track_sessions_unreachable_enr(&third_unreachable_node, &third_enr)
        });
        third_res
            .unwrap()
            .expect("should be space for third unreachable node");
    }
}
