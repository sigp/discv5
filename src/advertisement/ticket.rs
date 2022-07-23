use super::*;
use crate::{
    rpc::{RequestId, Ticket},
    service::ActiveRequest,
};
use delay_map::HashMapDelay;
use enr::NodeId;
use more_asserts::debug_unreachable;
use node_info::NodeContact;
use std::{cmp::Eq, collections::hash_map::Entry};

/// The max wait time accpeted for tickets.
pub const MAX_WAIT_TIME_TICKET: u64 = 60 * 5;

/// The time window within in which the number of new tickets from a peer for a topic will be limitied.
pub const TICKET_LIMIT_DURATION: Duration = Duration::from_secs(60 * 15);

/// Max tickets that are stored for an individual node for a topic (in the configured
/// time period).
pub const MAX_TICKETS_NODE_TOPIC: u8 = 3;

/// The time window in which tickets are accepted for any given free ad slot.
const REGISTRATION_WINDOW_IN_SECS: u64 = 10;

/// Max nodes that are considered in the selection process for an ad slot.
//const MAX_REGISTRANTS_AD_SLOT: usize = 50;

/// The duration for which requests are stored.
const REQUEST_TIMEOUT_IN_SECS: u64 = 15;

/// Each REGTOPIC request gets a TICKET response, NODES response and can get
/// a REGCONFIRMATION response.
const MAX_RESPONSES_REGTOPIC: u8 = 3;

/// A topic is active when it's associated with the NodeId from a node it is
/// published on.
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ActiveTopic {
    /// NodeId of the sender of the TICKET response.
    node_id: NodeId,
    /// The topic hash as it is sent in the TICKET response.
    topic: TopicHash,
}

impl ActiveTopic {
    /// Makes a topic active (currently associated with an ad slot or a ticket) by
    /// associating it with a node id.
    pub fn new(node_id: NodeId, topic: TopicHash) -> Self {
        ActiveTopic { node_id, topic }
    }

    /// Returns the topic of a topic that is active.
    pub fn topic(&self) -> TopicHash {
        self.topic
    }

    /// Returns the node id of a topic that is active.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
}

/// A ticket is active when it is associated with the node contact of
/// the sender of the ticket.
pub struct ActiveTicket {
    /// Node Contact of the sender of the ticket.
    contact: NodeContact,
    /// The ticket, an opaque object to the receiver.
    ticket: Vec<u8>,
}

impl ActiveTicket {
    /// Makes a ticket active (currently stored waiting to be used in a new registration
    /// attempt when its ticket wait time has expired) by associating it with a node
    /// contact.
    pub fn new(contact: NodeContact, ticket: Vec<u8>) -> Self {
        ActiveTicket { contact, ticket }
    }

    /// Returns the node contact of a ticket that is active.
    pub fn contact(&self) -> NodeContact {
        self.contact.clone()
    }

    /// Returns the ticket of a ticket that is active.
    pub fn ticket(&self) -> Vec<u8> {
        self.ticket.clone()
    }
}

/// Tickets holds the tickets recieved in TICKET responses to locally initiated
/// REGTOPIC requests.
pub struct Tickets {
    /// Tickets maps an [`ActiveTopic`] to an [`ActiveTicket`].
    tickets: HashMapDelay<ActiveTopic, ActiveTicket>,
    /// TicketHistory sets a time limit to how many times the [`ActiveTicket`]
    /// value in tickets can be updated within a given ticket limit duration.
    ticket_history: TicketHistory,
}

impl Tickets {
    pub fn new(ticket_limiter_duration: Duration) -> Self {
        Tickets {
            tickets: HashMapDelay::new(Duration::default()),
            ticket_history: TicketHistory::new(ticket_limiter_duration),
        }
    }

    pub fn default() -> Self {
        Tickets::new(TICKET_LIMIT_DURATION)
    }

    /// Inserts a ticket into [`Tickets`] if the state of [`TicketHistory`] allows it.
    pub fn insert(
        &mut self,
        contact: NodeContact,
        ticket: Vec<u8>,
        wait_time: Duration,
        topic: TopicHash,
    ) -> Result<(), &str> {
        let active_topic = ActiveTopic::new(contact.node_id(), topic);

        self.ticket_history.insert(active_topic.clone())?;

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

/// A PendingTicket maps to a Ticket received by another node in Tickets upon insert.
#[derive(Clone)]
struct PendingTicket {
    /// The ActiveTopic serves to match the Ticket to an entry in Tickets'
    /// tickets HashMapDelay.
    active_topic: ActiveTopic,
    /// The insert_time is used to check MAX_TICKETS_PER_NODE_TOPIC against
    /// the ticket_limiter_duration.
    insert_time: Instant,
}

/// TicketHistory keeps track of how many times a ticket was replaced for
/// an ActiveTopic within the time limit given by ticket_limiter_duration
/// and limits it to MAX_TICKETS_PER_NODE_TOPIC times.
#[derive(Default)]
pub struct TicketHistory {
    /// The ticket_count keeps track of how many tickets are stored for the
    /// ActiveTopic.
    ticket_count: HashMap<ActiveTopic, u8>,
    /// Up to MAX_TICKETS_PER_NODE_TOPIC PendingTickets in expirations maps
    /// to an ActiveTopic in ticket_count.
    expirations: VecDeque<PendingTicket>,
    /// The time a PendingTicket remains in expirations.
    ticket_limit_duration: Duration,
}

impl TicketHistory {
    fn new(ticket_limit_duration: Duration) -> Self {
        TicketHistory {
            ticket_count: HashMap::new(),
            expirations: VecDeque::new(),
            ticket_limit_duration,
        }
    }

    /// Inserts a ticket into [`TicketHistory`] unless the ticket of the given active
    /// topic has already been updated the limit amount of [`MAX_TICKETS_NODE_TOPIC`]
    /// times per ticket limit duration, then it is discarded and an error is returned.
    /// Expired entries are removed before insertion.
    pub fn insert(&mut self, active_topic: ActiveTopic) -> Result<(), &str> {
        self.remove_expired();
        let insert_time = Instant::now();
        let count = self.ticket_count.entry(active_topic.clone()).or_default();
        if *count >= MAX_TICKETS_NODE_TOPIC {
            debug!(
                "Max {} tickets per NodeId - Topic mapping accepted in {} minutes",
                MAX_TICKETS_NODE_TOPIC,
                self.ticket_limit_duration.as_secs()
            );
            return Err("Ticket limit reached");
        }
        *count += 1;
        self.expirations.push_back(PendingTicket {
            active_topic,
            insert_time,
        });
        Ok(())
    }

    /// Removes entries that have been stored for at least the ticket limit duration.
    /// If the same [`ActiveTopic`] is inserted again the count up till
    /// [`MAX_TICKETS_NODE_TOPIC`] inserts/updates starts anew.
    fn remove_expired(&mut self) {
        let now = Instant::now();
        let ticket_limiter_duration = self.ticket_limit_duration;
        let ticket_count = &mut self.ticket_count;
        let total_to_remove = self
            .expirations
            .iter()
            .take_while(|pending_ticket| {
                now.saturating_duration_since(pending_ticket.insert_time) >= ticket_limiter_duration
            })
            .map(|pending_ticket| {
                let count = ticket_count
                    .entry(pending_ticket.active_topic.clone())
                    .or_default();
                if *count > 1 {
                    *count -= 1;
                } else {
                    ticket_count.remove(&pending_ticket.active_topic);
                }
            })
            .count();

        for _ in 0..total_to_remove {
            self.expirations.pop_front();
        }
    }
}

/// The RegistrationWindow is the time from when an ad slot becomes free until no more
/// registration attempts are accepted for the ad slot.
#[derive(Clone)]
struct RegistrationWindow {
    /// The RegistrationWindow exists for a specific ad slot, so for a specific topic.
    topic: TopicHash,
    /// The open_time is used to make sure the RegistrationWindow closes after
    /// REGISTRATION_WINDOW_IN_SECS.
    open_time: Instant,
}

/// The tickets that will be considered for an ad slot.
pub struct PoolTicket {
    /// The node record of the node that returned the ticket.
    enr: Enr,
    /// The request id of the REGTOPIC that the ticket was returned in.
    req_id: RequestId,
    /// The returned ticket.
    ticket: Ticket,
    /// The ip address of the node that returned the ticket.
    ip: IpAddr,
}

impl PoolTicket {
    pub fn new(enr: Enr, req_id: RequestId, ticket: Ticket, ip: IpAddr) -> Self {
        PoolTicket {
            enr,
            req_id,
            ticket,
            ip,
        }
    }

    pub fn node_record(&self) -> &Enr {
        &self.enr
    }

    pub fn req_id(&self) -> &RequestId {
        &self.req_id
    }

    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }

    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }
}

/// The TicketPools collects all the registration attempts for a free ad slot.
#[derive(Default)]
pub struct TicketPools {
    /// The ticket_pools keeps track of all the registrants and their Tickets. One
    /// ticket pool per TopicHash can be open at a time. A ticket pool collects the
    /// valid tickets received within the registration window for a topic.
    ticket_pools: HashMap<TopicHash, HashMap<NodeId, PoolTicket>>,
    /// The expirations keeps track of when to close a ticket pool so the next one
    /// can be opened.
    expirations: VecDeque<RegistrationWindow>,
}

impl TicketPools {
    pub fn insert(&mut self, _node_record: Enr, _req_id: RequestId, _ticket: Ticket, _ip: IpAddr) {
        /*if let Some(open_time) = ticket.req_time().checked_add(ticket.wait_time()) {
            if open_time.elapsed() <= Duration::from_secs(REGISTRATION_WINDOW_IN_SECS) {
                let pool = self.ticket_pools.entry(ticket.topic()).or_default();
                // Drop request if pool contains 50 nodes, these nodes are out of luck and
                // won't be automatically included in next registration window for this topic
                if pool.len() < MAX_REGISTRANTS_AD_SLOT {
                    if pool.is_empty() {
                        self.expirations.push_back(RegistrationWindow {
                            topic: ticket.topic(),
                            open_time,
                        });
                    }
                    pool.insert(
                        node_record.node_id(),
                        PoolTicket::new(node_record, req_id, ticket, ip),
                    );
                }
            }
        }*/
    }
}

impl Stream for TicketPools {
    type Item = Result<(TopicHash, HashMap<NodeId, PoolTicket>), String>;
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

/// Since according to spec, a REGTOPIC request can receive both a TICKET and
/// then REGISTRATION_WINDOW_IN_SECS seconds later optionally also a
/// REGCONFIRMATION response, ActiveRegtopicRequests need to be handled separate
/// from ActiveRequests in Service.
#[derive(Clone)]
pub struct ActiveRegtopicRequest {
    /// The RequestId identifies an ActiveRequest.
    req_id: RequestId,
    /// The insert_time is used to make sure an ActiveRegtopicRequest persists
    /// no longer than REQUEST_TIMEOUT_IN_SECS.
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

/// The ActiveRegtopicRequests keeps ActiveRequests until they have matched
/// with MAX_RESPONSES_PER_REGTOPIC responses.
#[derive(Default)]
pub struct ActiveRegtopicRequests {
    requests: HashMap<RequestId, ActiveRequest>,
    request_history: HashMap<RequestId, u8>,
    expirations: VecDeque<ActiveRegtopicRequest>,
}

impl ActiveRegtopicRequests {
    /// Checks if there are currently any active REGTOPIC requests.
    pub fn is_empty(&self) -> bool {
        self.expirations.is_empty()
    }

    /// Returns the total amount of REGTOPIC requests currently active.
    pub fn len(&self) -> usize {
        self.expirations.len()
    }

    /// Removes a specific REGTOPIC request if it exists.
    pub fn remove(&mut self, req_id: &RequestId) -> Option<ActiveRequest> {
        if let Some(seen_count) = self.request_history.get_mut(req_id) {
            *seen_count += 1;
            if *seen_count == 0 {
                self.request_history.remove(req_id);
                self.requests.remove(req_id)
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

    /// Caution! Reinsert should only be called if a NODES response to a REGTOPIC needs to be divided
    /// into multiple NODES responses, the request must be reinserted.
    pub fn reinsert(&mut self, req_id: RequestId) {
        self.remove_expired();
        if let Entry::Occupied(ref mut entry) = self.request_history.entry(req_id) {
            *entry.get_mut() += 1;
        }
    }

    /// Inserts a REGTOPIC request into [`ActiveRegtopicRequests`] after removing timed out [`ActiveRegtopicRequest`]s.
    pub fn insert(&mut self, req_id: RequestId, req: ActiveRequest) {
        self.remove_expired();
        let now = Instant::now();

        self.requests.insert(req_id.clone(), req);
        self.request_history
            .insert(req_id.clone(), MAX_RESPONSES_REGTOPIC);
        self.expirations
            .push_back(ActiveRegtopicRequest::new(req_id, now));
    }

    /// If a REGTOPIC request doesn't receive the expected responses it times out, and calling this
    /// function will remove timed out entries.
    fn remove_expired(&mut self) {
        let mut expired = Vec::new();
        self.expirations
            .iter()
            .take_while(|req| {
                req.insert_time.elapsed() >= Duration::from_secs(REQUEST_TIMEOUT_IN_SECS)
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
