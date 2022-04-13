use super::*;
use crate::rpc::{RequestId, Ticket};
use delay_map::HashMapDelay;
use enr::NodeId;
use node_info::NodeContact;
use std::{cmp::Eq, collections::HashSet};

// Placeholder function
pub fn topic_hash(topic: Vec<u8>) -> Topic {
    let mut topic_hash = [0u8; 32];
    topic_hash[32 - topic.len()..].copy_from_slice(&topic);
    topic_hash
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct ActiveTopic {
    node_id: NodeId,
    topic: Topic,
}

impl ActiveTopic {
    pub fn new(node_id: NodeId, topic: Topic) -> Self {
        ActiveTopic { node_id, topic }
    }

    pub fn topic(&self) -> Topic {
        self.topic
    }
}

pub struct ActiveTicket {
    contact: NodeContact,
    ticket: Ticket,
}

impl ActiveTicket {
    pub fn new(contact: NodeContact, ticket: Ticket) -> Self {
        ActiveTicket { contact, ticket }
    }

    pub fn contact(&self) -> NodeContact {
        self.contact.clone()
    }

    pub fn ticket(&self) -> Ticket {
        self.ticket
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
        ticket: Ticket,
        wait_time: Duration,
    ) -> Result<(), &str> {
        let active_topic = ActiveTopic::new(contact.node_id(), ticket.topic());

        if let Err(e) = self.ticket_history.insert(active_topic) {
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

struct TicketRateLimiter {
    active_topic: ActiveTopic,
    first_seen: Instant,
}

#[derive(Default)]
struct TicketHistory {
    ticket_cache: HashMap<ActiveTopic, u8>,
    expirations: VecDeque<TicketRateLimiter>,
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
        let count = self.ticket_cache.entry(active_topic).or_default();
        if *count >= 3 {
            error!("Max 3 tickets per (NodeId, Topic) accepted in 15 minutes");
            return Err("Ticket limit reached");
        }
        *count += 1;
        Ok(())
    }

    fn remove_expired(&mut self) {
        let now = Instant::now();
        let cached_tickets = self
            .expirations
            .iter()
            .take_while(|ticket_limiter| {
                now.saturating_duration_since(ticket_limiter.first_seen)
                    >= self.ticket_cache_duration
            })
            .map(|ticket_limiter| ticket_limiter.active_topic)
            .collect::<Vec<ActiveTopic>>();

        cached_tickets.iter().for_each(|active_topic| {
            self.ticket_cache.remove(active_topic);
            self.expirations.pop_front();
        });
    }
}

#[derive(Clone, Copy)]
struct RegistrationWindow {
    topic: Topic,
    open_time: Instant,
}

pub struct TicketPools {
    ticket_pools: HashMap<Topic, HashMap<NodeId, (Enr, RequestId, Ticket)>>,
    expirations: VecDeque<RegistrationWindow>,
}

impl TicketPools {
    pub fn new() -> Self {
        TicketPools {
            ticket_pools: HashMap::new(),
            expirations: VecDeque::new(),
        }
    }

    pub fn insert(&mut self, node_record: Enr, req_id: RequestId, ticket: Ticket) {
        if let Some(open_time) = ticket.req_time().checked_add(ticket.wait_time()) {
            if open_time.elapsed() <= Duration::from_secs(10) {
                let pool = self.ticket_pools.entry(ticket.topic()).or_default();
                // Drop request if pool contains 50 nodes
                if pool.len() < 50 {
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
    type Item = Result<(Topic, HashMap<NodeId, (Enr, RequestId, Ticket)>), String>;
    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.expirations
            .pop_front()
            .map(|reg_window| {
                if reg_window.open_time.elapsed() > Duration::from_secs(10) {
                    self.ticket_pools
                        .remove_entry(&reg_window.topic)
                        .map(|(topic, ticket_pool)| {
                            self.expirations.pop_front();
                            Poll::Ready(Some(Ok((topic, ticket_pool))))
                        })
                        .unwrap_or_else(|| Poll::Ready(Some(Err("Ticket selection failed".into()))))
                } else {
                    Poll::Pending
                }
            })
            .unwrap_or(Poll::Pending)
    }
}

#[derive(Clone, Copy)]
pub struct ActiveRegtopicRequest {
    active_topic: ActiveTopic,
    insert_time: Instant,
}

impl ActiveRegtopicRequest {
    fn new(active_topic: ActiveTopic, insert_time: Instant) -> Self {
        ActiveRegtopicRequest {
            active_topic,
            insert_time,
        }
    }
}

pub struct ActiveRegtopicRequests {
    requests: HashMap<ActiveTopic, HashSet<RequestId>>,
    expirations: VecDeque<ActiveRegtopicRequest>,
}

impl ActiveRegtopicRequests {
    pub fn new() -> Self {
        ActiveRegtopicRequests {
            requests: HashMap::new(),
            expirations: VecDeque::new(),
        }
    }

    pub fn is_active_req(
        &mut self,
        req_id: RequestId,
        node_id: NodeId,
        topic: Topic,
    ) -> Option<bool> {
        self.remove_expired();
        self.requests
            .remove(&ActiveTopic::new(node_id, topic))
            .map(|ids| ids.contains(&req_id))
    }

    pub fn insert(&mut self, node_id: NodeId, topic: Topic, req_id: RequestId) {
        self.remove_expired();
        let now = Instant::now();
        let active_topic = ActiveTopic::new(node_id, topic);

        // Since a REGTOPIC request always receives a TICKET response, when we come to register with a ticket which
        // wait-time is up we get a TICKET response with wait-time 0, hence we initiate a new REGTOPIC request.
        // Since the registration window is 10 seconds, incase we would receive a RECONGIRMATION for that first
        // REGTOPIC, that req-id would have been replaced, so we use a set. We extend the req-id set life-time upon
        // each insert incase a REGCONFIRMATION comes to a later req-id. Max req-ids in a set is limited by our
        // implementation accepting max 3 tickets for a (NodeId, Topic) within 15 minutes.
        self.requests
            .entry(active_topic)
            .or_default()
            .insert(req_id);
        self.expirations
            .iter()
            .enumerate()
            .find(|(_, req)| req.active_topic == active_topic)
            .map(|(index, _)| index)
            .map(|index| self.expirations.remove(index));
        self.expirations
            .push_back(ActiveRegtopicRequest::new(active_topic, now));
    }

    fn remove_expired(&mut self) {
        self.expirations
            .iter()
            .take_while(|req| req.insert_time.elapsed() >= Duration::from_secs(15))
            .copied()
            .collect::<Vec<_>>()
            .iter()
            .for_each(|req| {
                self.requests.remove(&req.active_topic);
                self.expirations.pop_front();
            });
    }
}
