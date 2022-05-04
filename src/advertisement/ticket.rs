use super::*;
use crate::{
    rpc::{RequestId, Ticket},
    service::ActiveRequest,
};
use delay_map::HashMapDelay;
use enr::NodeId;
use more_asserts::debug_unreachable;
use node_info::NodeContact;
use std::cmp::Eq;

// Max tickets that are stored from one node for a topic (in the configured
// time period)
const MAX_TICKETS_PER_NODE_TOPIC: u8 = 3;
//
const REGISTRATION_WINDOW_IN_SECS: u64 = 10;
// Max nodes that are considered in the selection process for an ad slot.
const MAX_REGISTRANTS_PER_AD_SLOT: usize = 50;

const MAX_CACHE_TIME_IN_SECS: u64 = 15;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ActiveTopic {
    node_id: NodeId,
    topic: TopicHash,
}

impl ActiveTopic {
    pub fn new(node_id: NodeId, topic: TopicHash) -> Self {
        ActiveTopic { node_id, topic }
    }

    pub fn topic(&self) -> TopicHash {
        self.topic
    }
}

pub struct ActiveTicket {
    contact: NodeContact,
    ticket: Vec<u8>,
}

impl ActiveTicket {
    pub fn new(contact: NodeContact, ticket: Vec<u8>) -> Self {
        ActiveTicket { contact, ticket }
    }

    pub fn contact(&self) -> NodeContact {
        self.contact.clone()
    }

    pub fn ticket(&self) -> Vec<u8> {
        self.ticket.clone()
    }
}

/// Tickets received from other nodes as response to REGTOPIC req
pub struct Tickets {
    tickets: HashMapDelay<ActiveTopic, ActiveTicket>,
    ticket_history: TicketHistory,
}

impl Tickets {
    pub fn new(ticket_cache_duration: Duration) -> Self {
        Tickets {
            tickets: HashMapDelay::new(Duration::default()),
            ticket_history: TicketHistory::new(ticket_cache_duration),
        }
    }

    pub fn insert(
        &mut self,
        contact: NodeContact,
        ticket: Vec<u8>,
        wait_time: Duration,
        topic: TopicHash,
    ) -> Result<(), &str> {
        let active_topic = ActiveTopic::new(contact.node_id(), topic);

        if let Err(e) = self.ticket_history.insert(active_topic.clone()) {
            return Err(e);
        }
        self.tickets
            .insert_at(active_topic, ActiveTicket::new(contact, ticket), wait_time);
        Ok(())
    }
}

impl Stream for Tickets {
    type Item = Result<(ActiveTopic, ActiveTicket), String>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.tickets.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok((active_topic, ticket)))) => {
                Poll::Ready(Some(Ok((active_topic, ticket))))
            }
            Poll::Ready(Some(Err(e))) => {
                debug!("{}", e);
                Poll::Pending
            }
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }
    }
}

// The PendingTicket has an ActiveTopic that maps to a ticket in Tickets
#[derive(Clone)]
struct PendingTicket {
    active_topic: ActiveTopic,
    insert_time: Instant,
}

#[derive(Default)]
struct TicketHistory {
    ticket_cache: HashMap<ActiveTopic, u8>,
    expirations: VecDeque<PendingTicket>,
    ticket_cache_duration: Duration,
}

impl TicketHistory {
    fn new(ticket_cache_duration: Duration) -> Self {
        TicketHistory {
            ticket_cache: HashMap::new(),
            expirations: VecDeque::new(),
            ticket_cache_duration,
        }
    }

    pub fn insert(&mut self, active_topic: ActiveTopic) -> Result<(), &str> {
        self.remove_expired();
        let insert_time = Instant::now();
        let count = self.ticket_cache.entry(active_topic.clone()).or_default();
        if *count >= MAX_TICKETS_PER_NODE_TOPIC {
            error!("Max 3 tickets per (NodeId, Topic) accepted in 15 minutes");
            return Err("Ticket limit reached");
        }
        *count += 1;
        self.expirations.push_back(PendingTicket {
            active_topic,
            insert_time,
        });
        Ok(())
    }

    fn remove_expired(&mut self) {
        let now = Instant::now();
        let ticket_cache_duration = self.ticket_cache_duration;
        let ticket_cache = &mut self.ticket_cache;
        let total_to_remove = self
            .expirations
            .iter()
            .take_while(|pending_ticket| {
                now.saturating_duration_since(pending_ticket.insert_time) >= ticket_cache_duration
            })
            .map(|pending_ticket| {
                let count = ticket_cache
                    .entry(pending_ticket.active_topic.clone())
                    .or_default();
                if *count > 1 {
                    *count -= 1;
                } else {
                    ticket_cache.remove(&pending_ticket.active_topic);
                }
            })
            .count();

        for _ in 0..total_to_remove {
            self.expirations.pop_front();
        }
    }
}

#[derive(Clone)]
struct RegistrationWindow {
    topic: TopicHash,
    open_time: Instant,
}

#[derive(Default)]
pub struct TicketPools {
    ticket_pools: HashMap<TopicHash, HashMap<NodeId, (Enr, RequestId, Ticket)>>,
    expirations: VecDeque<RegistrationWindow>,
}

impl TicketPools {
    pub fn insert(&mut self, node_record: Enr, req_id: RequestId, ticket: Ticket) {
        if let Some(open_time) = ticket.req_time().checked_add(ticket.wait_time()) {
            if open_time.elapsed() <= Duration::from_secs(REGISTRATION_WINDOW_IN_SECS) {
                let pool = self.ticket_pools.entry(ticket.topic()).or_default();
                // Drop request if pool contains 50 nodes, these nodes are out of luck and
                // won't be automatically included in next registration window for this topic
                if pool.len() < MAX_REGISTRANTS_PER_AD_SLOT {
                    if pool.is_empty() {
                        self.expirations.push_back(RegistrationWindow {
                            topic: ticket.topic(),
                            open_time,
                        });
                    }
                    pool.insert(node_record.node_id(), (node_record, req_id, ticket));
                }
            }
        }
    }
}

impl Stream for TicketPools {
    type Item = Result<(TopicHash, HashMap<NodeId, (Enr, RequestId, Ticket)>), String>;
    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let ticket_pool = self.expirations.front();
        if let Some(reg_window) = ticket_pool {
            if reg_window.open_time.elapsed() < Duration::from_secs(REGISTRATION_WINDOW_IN_SECS) {
                return Poll::Pending;
            }
        } else {
            return Poll::Pending;
        }
        self.expirations
            .pop_front()
            .map(|reg_window| {
                self.ticket_pools
                    .remove_entry(&reg_window.topic)
                    .map(|(topic, ticket_pool)| {
                        self.expirations.pop_front();
                        Poll::Ready(Some(Ok((topic, ticket_pool))))
                    })
                    .unwrap_or_else(|| {
                        debug_unreachable!(
                            "Mismatched mapping between ticket_pools and expirations invariant"
                        );
                        Poll::Pending
                    })
            })
            .unwrap_or(Poll::Pending)
    }
}

#[derive(Clone)]
pub struct ActiveRegtopicRequest {
    req_id: RequestId,
    insert_time: Instant,
}

impl ActiveRegtopicRequest {
    fn new(req_id: RequestId, insert_time: Instant) -> Self {
        ActiveRegtopicRequest {
            insert_time,
            req_id,
        }
    }
}

#[derive(Default)]
pub struct ActiveRegtopicRequests {
    requests: HashMap<RequestId, ActiveRequest>,
    request_history: HashMap<RequestId, u8>,
    expirations: VecDeque<ActiveRegtopicRequest>,
}

impl ActiveRegtopicRequests {
    pub fn remove(&mut self, req_id: &RequestId) -> Option<ActiveRequest> {
        if let Some(seen_count) = self.request_history.get_mut(req_id) {
            *seen_count += 1;
            if *seen_count < 1 {
                self.request_history.remove(req_id);
                self.requests.remove(req_id).map(|req| ActiveRequest {
                    contact: req.contact.clone(),
                    request_body: req.request_body.clone(),
                    query_id: req.query_id,
                    callback: None,
                })
            } else {
                self.requests.get(req_id).map(|req| ActiveRequest {
                    contact: req.contact.clone(),
                    request_body: req.request_body.clone(),
                    query_id: req.query_id,
                    callback: None,
                })
            }
        } else {
            None
        }
    }

    pub fn insert(&mut self, req_id: RequestId, req: ActiveRequest) {
        self.remove_expired();
        let now = Instant::now();

        self.requests.insert(req_id.clone(), req);
        // Each request id can be used twice, once for a TICKET response and
        // once for a REGCONFIRMATION response
        self.request_history.insert(req_id.clone(), 2);
        self.expirations
            .push_back(ActiveRegtopicRequest::new(req_id, now));
    }

    fn remove_expired(&mut self) {
        let mut expired = Vec::new();
        self.expirations
            .iter()
            .take_while(|req| {
                req.insert_time.elapsed() >= Duration::from_secs(MAX_CACHE_TIME_IN_SECS)
            })
            .for_each(|req| {
                expired.push(req.clone());
            });

        expired.into_iter().for_each(|req| {
            self.requests.remove(&req.req_id);
            self.request_history.remove(&req.req_id);
            self.expirations.pop_front();
        });
    }
}
