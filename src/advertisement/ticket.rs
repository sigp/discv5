use super::*;
use crate::node_info::NodeAddress;
use delay_map::HashMapDelay;

// Temporary, some hash function will probably be used here instead of padding
pub fn topic_hash(topic: Vec<u8>) -> Result<Topic, String> {
    if topic.len() > 32 {
        return Err("Topic is greater than 32 bytes".into());
    }
    let mut topic_hash = [0u8; 32];
    topic_hash[32 - topic.len()..].copy_from_slice(&topic);
    Ok(topic_hash)
}

pub struct Ticket {
    //nonce: u64,
    //src_node_id: NodeId,
    //src_ip: IpAddr,
    topic: Topic,
    //req_time: Instant,
    //wait_time: Duration,
    //cum_wait: Duration,*/
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
        Ticket{
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
        Ok(Ticket{topic: [0u8; 32]})
    }
}

pub struct Tickets {
    tickets: HashMapDelay<(NodeAddress, Topic), Ticket>
}

impl Tickets {
    pub fn new() -> Self {
        Tickets{
            tickets: HashMapDelay::new(Duration::default()),
        }
    }

    pub fn insert(&mut self, node_address: NodeAddress, ticket: Ticket, wait_time: Duration) {
        self.tickets.insert_at((node_address, ticket.topic), ticket, wait_time);
    }
}

impl Stream for Tickets {
    type Item = Result<(NodeAddress, Ticket), String>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.tickets.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(((node_address, _), ticket)))) => Poll::Ready(Some(Ok((node_address, ticket)))),
            Poll::Ready(Some(Err(e))) => {
                debug!("{}", e);
                Poll::Pending
            },
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }   
    }
}