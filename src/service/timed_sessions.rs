//! A simple data structure for managing the timeouts of sessions.
//!
//! This stores a hashmap of Sessions coupled with a delay queue to indicate when a session has
//! expired.

use crate::session::Session;
use enr::NodeId;
use futures::Stream;
use log::error;
use std::pin::Pin;
use std::{
    collections::HashMap,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{delay_queue, DelayQueue};

/// A collection of sessions and associated timeouts.
///
/// Sessions have an establishment timeout as
/// well as lifetime.
pub(crate) struct TimedSessions {
    /// The sessions being established.
    sessions: HashMap<NodeId, (Session, delay_queue::Key)>,
    /// A queue indicating when a session has timed out.
    timeouts: DelayQueue<NodeId>,
    /// The time to wait for a session to be established.
    session_establish_timeout: Duration,
}

impl TimedSessions {
    pub(crate) fn new(session_establish_timeout: Duration) -> Self {
        TimedSessions {
            sessions: HashMap::new(),
            timeouts: DelayQueue::new(),
            session_establish_timeout,
        }
    }

    pub(crate) fn insert(&mut self, node_id: NodeId, session: Session) {
        self.insert_at(node_id, session, self.session_establish_timeout);
    }

    pub(crate) fn insert_at(&mut self, node_id: NodeId, session: Session, duration: Duration) {
        if self.contains(&node_id) {
            // update the timeout
            self.update_timeout(&node_id, duration);
        } else {
            let delay = self.timeouts.insert(node_id.clone(), duration);

            self.sessions.insert(node_id, (session, delay));
        }
    }

    pub(crate) fn get(&self, node_id: &NodeId) -> Option<&Session> {
        self.sessions.get(node_id).map(|&(ref v, _)| v)
    }

    pub(crate) fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut Session> {
        self.sessions.get_mut(node_id).map(|(v, _)| v)
    }

    /// Returns true if the key exists, false otherwise.
    pub(crate) fn contains(&self, node_id: &NodeId) -> bool {
        self.sessions.contains_key(node_id)
    }

    pub(crate) fn update_timeout(&mut self, node_id: &NodeId, timeout: Duration) {
        if let Some((_, key)) = self.sessions.get(node_id) {
            self.timeouts.reset(key, timeout);
        }
    }

    pub(crate) fn remove(&mut self, node_id: &NodeId) {
        if let Some((_, delay_key)) = self.sessions.remove(node_id) {
            self.timeouts.remove(&delay_key);
        }
    }
}

impl Stream for TimedSessions {
    type Item = (NodeId, Session);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.timeouts.poll_expired(cx) {
            Poll::Ready(Some(Ok(node_id))) => {
                let node_id = node_id.into_inner();
                if let Some((session, _)) = self.sessions.remove(&node_id) {
                    Poll::Ready(Some((node_id, session)))
                } else {
                    error!("Session no longer exists");
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(e))) => {
                error!("Session timeout error: {:?}", e);
                Poll::Pending
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
