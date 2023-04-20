use crate::{node_info::NodeAddress, Discv5Error, Enr};
use std::collections::HashSet;
use tracing::warn;

/// The minimum number of peers to accept sessions with that have an unreachable ENR, i.e. cater
/// requests for, at a time. Benevolent peers of this type could for example be symmetrically
/// NAT:ed nodes or nodes that have recently joined the network and are still unaware of their
/// externally reachable socket, relying on their peers to discover it.
pub const MIN_SESSIONS_UNREACHABLE_ENR: usize = 1;
/// The default number of peers to accept sessions with that have an unreachable ENR.
pub const DEFAULT_SESSIONS_UNREACHABLE_ENR: usize = 250;

pub(crate) struct SessionLimiter {
    /// Keeps track of the sessions held for peers with unreachable ENRs. These could be peers yet
    /// to discover their externally reachable socket or symmetrically NAT:ed peers that,
    /// naturally, will never discover one externally reachable socket.
    sessions_unreachable_enr_tracker: HashSet<NodeAddress>,
    /// Receiver of expired sessions.
    rx_expired_sessions: futures::channel::mpsc::Receiver<NodeAddress>,
    /// The max number of sessions to peers with unreachable ENRs at a time.
    limit: usize,
}

impl SessionLimiter {
    pub fn new(
        rx_expired_sessions: futures::channel::mpsc::Receiver<NodeAddress>,
        unreachable_enr_limit: Option<usize>,
    ) -> Self {
        let limit = match unreachable_enr_limit {
            Some(peer_count) => {
                if peer_count < MIN_SESSIONS_UNREACHABLE_ENR {
                    warn!(
                        "unreachable ENR limit from config too low, setting to minimum {}",
                        MIN_SESSIONS_UNREACHABLE_ENR
                    );
                    MIN_SESSIONS_UNREACHABLE_ENR
                } else {
                    peer_count
                }
            }
            None => DEFAULT_SESSIONS_UNREACHABLE_ENR,
        };
        SessionLimiter {
            sessions_unreachable_enr_tracker: Default::default(),
            rx_expired_sessions,
            limit,
        }
    }

    // Checks if a session with this peer should be allowed at this given time.
    pub fn track_sessions_unreachable_enr(
        &mut self,
        node_address: &NodeAddress,
        enr: &Enr,
    ) -> Result<(), Discv5Error> {
        // Empty buffer of expired sessions, and remove any which belong to unreachable ENRs.
        while let Ok(Some(session_index)) = self.rx_expired_sessions.try_next() {
            self.sessions_unreachable_enr_tracker.remove(&session_index);
        }
        if enr.udp4_socket().is_none() && enr.udp6_socket().is_none() {
            // Peer is unreachable
            if self.sessions_unreachable_enr_tracker.len() >= self.limit {
                return Err(Discv5Error::LimitSessionsUnreachableEnr);
            }
            self.sessions_unreachable_enr_tracker
                .insert(node_address.clone());
        }
        Ok(())
    }
}
