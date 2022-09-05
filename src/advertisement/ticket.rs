use super::*;
use crate::Topic;
use delay_map::HashMapDelay;
use enr::NodeId;
use node_info::NodeContact;
use std::{cmp::Eq, hash::Hash};

/// The max wait time accpeted for tickets.
pub const MAX_WAIT_TIME_TICKET: u64 = 60 * 5;

/// The time window within which the number of new tickets from a peer for a topic will be limitied.
pub const TICKET_LIMIT_DURATION: Duration = Duration::from_secs(60 * 15);

/// Max tickets that are stored for an individual node for a topic (in the configured
/// time period).
pub const MAX_TICKETS_NODE_TOPIC: u8 = 3;

/// A topic is active when it's associated with the NodeId from a node it is
/// published on.
#[derive(PartialEq, Eq, Clone, Hash)]
pub struct ActiveTopic {
    /// NodeId of the sender of the TICKET response.
    node_id: NodeId,
    /// The topic hash as it is sent in the TICKET response.
    topic: Topic,
}

impl ActiveTopic {
    /// Makes a topic active (currently associated with an ad slot or a ticket) by
    /// associating it with a node id.
    pub fn new(node_id: NodeId, topic: Topic) -> Self {
        ActiveTopic { node_id, topic }
    }

    /// Returns the topic of a topic that is active.
    pub fn topic(&self) -> &Topic {
        &self.topic
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
        topic: Topic,
    ) -> Result<(), &str> {
        let active_topic = ActiveTopic::new(contact.node_id(), topic);

        self.ticket_history.insert(active_topic.clone())?;

        self.tickets
            .insert_at(active_topic, ActiveTicket::new(contact, ticket), wait_time);
        Ok(())
    }

    /// Removes all tickets held for the given topic.
    pub fn remove(&mut self, topic: &Topic) {
        for (active_topic, _) in self.tickets.iter() {
            if active_topic.topic() == topic {
                self.tickets.remove(active_topic);
            }
        }
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
                error!(
                    "Failed to fetch next ticket with expired wait time. Error {}",
                    e
                );
                Poll::Ready(Some(Err(e)))
            }
            // When the hashmap delay holding tickets is empty, as we poll this tickets stream in a
            // select! statement, to avoid re-polling the stream till it fills up again with new
            // tickets pending a re-attempt at registration we return Poll::Pending.
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
    /// Up to [`MAX_TICKETS_PER_NODE_TOPIC`] PendingTickets in expirations map
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
