use super::*;
use delay_map::HashMapDelay;
use enr::NodeId;
use node_info::NodeContact;
use std::cmp::Eq;

// Placeholder function
pub fn topic_hash(topic: Vec<u8>) -> Topic {
    let mut topic_hash = [0u8; 32];
    topic_hash[32 - topic.len()..].copy_from_slice(&topic);
    topic_hash
}

#[derive(PartialEq, Eq, Hash, Clone)]
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

#[derive(Default, Debug, Copy, Clone)]
pub struct Ticket {
    //nonce: u64,
    //src_node_id: NodeId,
    //src_ip: IpAddr,
    topic: Topic,
    //req_time: Instant,
    //wait_time: Duration,
    //cum_wait: Option<Duration>,*/
}

impl Ticket {
    pub fn new(
        //nonce: u64,
        //src_node_id: NodeId,
        //src_ip: IpAddr,
        topic: Topic,
        //req_time: Instant,
        //wait_time: Duration,*/
    ) -> Self {
        Ticket {
            //nonce,
            //src_node_id,
            //src_ip,
            topic,
            //req_time,
            //wait_time,
        }
    }

    pub fn decode(ticket_bytes: Vec<u8>) -> Result<Self, String> {
        if ticket_bytes.is_empty() {
            return Err("Ticket has wrong format".into());
        }
        Ok(Ticket { topic: [0u8; 32] })
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

pub struct Tickets {
    tickets: HashMapDelay<ActiveTopic, ActiveTicket>,
}

impl Tickets {
    pub fn new() -> Self {
        Tickets {
            tickets: HashMapDelay::new(Duration::default()),
        }
    }

    pub fn insert(&mut self, contact: NodeContact, ticket: Ticket, wait_time: Duration) {
        self.tickets.insert_at(
            ActiveTopic::new(contact.node_id(), ticket.topic),
            ActiveTicket::new(contact, ticket),
            wait_time,
        );
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
