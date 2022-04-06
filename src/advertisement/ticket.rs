use super::*;
use crate::node_info::NodeAddress;
use delay_map::HashMapDelay;
use std::cmp::Eq;

pub fn topic_hash(topic: Vec<u8>) -> Result<Topic, String> {
    if topic.len() > 32 {
        return Err("Topic is greater than 32 bytes".into());
    }
    let mut topic_hash = [0u8; 32];
    topic_hash[32 - topic.len()..].copy_from_slice(&topic);
    Ok(topic_hash)
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct ActiveTopic {
    node_address: NodeAddress,
    topic: Topic,
}

impl ActiveTopic {
    pub fn new(node_address: NodeAddress, topic: Topic) -> Self {
        ActiveTopic {
            node_address,
            topic,
        }
    }

    pub fn topic(&self) -> Topic {
        self.topic
    }
}

#[derive(Default, Debug)]
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

    /*pub fn regconfirmation(&mut self, node_record: Enr<CombinedKey>, topic: Topic, ticket: Ticket) -> Result<(), String> {
        // chose which ad to insert from some pool of registrants-within-10-seconds-from-x
        Ok(())
    }*/
}

pub struct Tickets {
    tickets: HashMapDelay<ActiveTopic, Ticket>,
}

impl Tickets {
    pub fn new() -> Self {
        Tickets {
            tickets: HashMapDelay::new(Duration::default()),
        }
    }

    pub fn insert(&mut self, node_address: NodeAddress, ticket: Ticket, wait_time: Duration) {
        self.tickets.insert_at(
            ActiveTopic::new(node_address, ticket.topic),
            ticket,
            wait_time,
        );
    }
}

impl Stream for Tickets {
    type Item = Result<(ActiveTopic, Ticket), String>;
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
