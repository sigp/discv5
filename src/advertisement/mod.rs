use super::*;
use core::time::Duration;
use enr::{CombinedKey, Enr};
use futures::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::{sleep, Instant, Sleep};
use tracing::debug;

pub mod ticket;
mod test;

pub const MAX_ADS_PER_TOPIC: usize = 100;
pub const MAX_ADS: i32 = 5000;

type Topic = [u8; 32];

pub struct Ad {
    node_record: Enr<CombinedKey>,
    insert_time: Instant,
}

impl PartialEq for Ad {
    fn eq(&self, other: &Self) -> bool {
        self.node_record == other.node_record
    }
}
pub struct Ads {
    expirations: VecDeque<(Pin<Box<Sleep>>, Topic)>,
    ads: HashMap<Topic, VecDeque<Ad>>,
    total_ads: i32,
    ad_lifetime: Duration,
}

impl Ads {
    pub fn new(ad_lifetime: Duration) -> Self {
        Ads {
            expirations: VecDeque::new(),
            ads: HashMap::new(),
            total_ads: 0,
            ad_lifetime,
        }
    }

    pub fn get_ad_nodes(&self, topic: Topic) -> Result<Vec<Enr<CombinedKey>>, String> {
        match self.ads.get(&topic) {
            Some(topic_ads) => Ok(topic_ads.into_iter().map(|ad| ad.node_record.clone()).collect()),
            None => Err("No ads for this topic".into()),
        }
    }

    pub fn ticket_wait_time(&self, topic: Topic) -> Duration {
        let now = Instant::now();
        match self.ads.get(&topic) {
            Some(nodes) => {
                if nodes.len() < MAX_ADS_PER_TOPIC {
                    Duration::from_secs(0)
                } else {
                    match nodes.get(0) {
                        Some(ad) => {
                            let elapsed_time = now.saturating_duration_since(ad.insert_time);
                            self.ad_lifetime.saturating_sub(elapsed_time)
                        }
                        None => {
                            #[cfg(debug_assertions)]
                            panic!("Panic on debug,topic key should be deleted if no ad nodes queued for it");
                            #[cfg(not(debug_assertions))]
                            {
                                error!("Topic key should be deleted if no ad nodes queued for it");
                                return Poll::Ready(Err("No nodes for topic".into()));
                            }
                        }
                    }
                }
            }
            None => {
                if self.total_ads < MAX_ADS {
                    Duration::from_secs(0)
                } else {
                    match self.expirations.get(0) {
                        Some((fut, _)) => fut.deadline().saturating_duration_since(now),
                        None => {
                            #[cfg(debug_assertions)]
                            panic!("Panic on debug, mismatched mapping between expiration queue and total ads count");
                            #[cfg(not(debug_assertions))]
                            {
                                error!("Mismatched mapping between expiration queue and total ads count");
                                return Duration::from_secs(0);
                            }
                        }
                    }
                }
            }
        }
    }

    /*pub fn regconfirmation(&self, node_record: Enr<CombinedKey>, topic: Topic, ticket: Vec<u8>) -> Result<(), String> {
       // check if ticket is valid
        self.insert(node_record, topic);
    }*/

    fn insert(&mut self, node_record: Enr<CombinedKey>, topic: Topic) -> Result<(), String> {
        let now = Instant::now();
        if let Some(nodes) = self.ads.get_mut(&topic) {
            if nodes.contains(&Ad { node_record: node_record.clone(), insert_time: now }) {
                debug!("This node {} is already advertising this topic", node_record.node_id());
                return Err("Node already advertising this topic".into());
            }
            nodes.push_back(Ad { node_record, insert_time: now });
        } else {
            let mut nodes = VecDeque::new();
            nodes.push_back(Ad { node_record, insert_time: now });
            self.ads.insert(topic, nodes);
        }
        self.expirations
            .push_back((Box::pin(sleep(self.ad_lifetime)), topic));
        self.total_ads += 1;
        Ok(())
    }
}

impl Stream for Ads {
    // type returned can be unit type but for testing easier to get values, worth the overhead to keep?
    type Item = Result<((Enr<CombinedKey>, Instant), Topic), String>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (fut, topic) = match self.expirations.get_mut(0) {
            Some((fut, topic)) => (fut, *topic),
            None => {
                debug!("No ads in 'table'");
                return Poll::Pending;
            },
        };
        match fut.poll_unpin(cx) {
                Poll::Ready(()) => match self.ads.get_mut(&topic) {
                    Some(topic_ads) => {
                        match topic_ads.pop_front() {
                            Some(ad) => {
                                if topic_ads.is_empty() {
                                    self.ads.remove(&topic);
                                }
                                self.total_ads -= 1;
                                self.expirations.remove(0);
                                Poll::Ready(Some(Ok(((ad.node_record, ad.insert_time), topic))))
                            }
                            None => {
                                #[cfg(debug_assertions)]
                                panic!("Panic on debug, topic key should be deleted if no ad nodes queued for it");
                                #[cfg(not(debug_assertions))]
                                {
                                    error!("Topic key should be deleted if no ad nodes queued for it");
                                    return Poll::Ready(Err("No nodes for topic".into()));
                                }
                            }
                        }
                    }
                    None => {
                        #[cfg(debug_assertions)]
                        panic!("Panic on debug, mismatched mapping between expiration queue and entry queue");
                        #[cfg(not(debug_assertions))]
                        {
                            error!("Mismatched mapping between expiration queue and entry queue");
                            return Poll::Ready(Err("Topic doesn't exist".into()));
                        }
                    }
                },
                Poll::Pending => Poll::Pending,
            }
    }
}
