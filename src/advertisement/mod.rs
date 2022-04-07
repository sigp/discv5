use super::*;
use core::time::Duration;
use enr::{CombinedKey, Enr};
use futures::prelude::*;
use std::{
    collections::{vec_deque::Iter, HashMap, VecDeque},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::Instant;
use tracing::{debug, error};

mod test;
pub mod ticket;

pub type Topic = [u8; 32];

/// An ad we are adevrtising for another node
#[derive(Debug)]
pub struct Ad {
    node_record: Enr<CombinedKey>,
    insert_time: Instant,
}

impl Ad {
    pub fn new(node_record: Enr<CombinedKey>, insert_time: Instant) -> Self {
        Ad {
            node_record,
            insert_time,
        }
    }

    pub fn node_record(&self) -> &Enr<CombinedKey> {
        &self.node_record
    }
}

impl PartialEq for Ad {
    fn eq(&self, other: &Self) -> bool {
        self.node_record == other.node_record
    }
}
pub struct Ads {
    expirations: VecDeque<(Instant, Topic)>,
    ads: HashMap<Topic, VecDeque<Ad>>,
    total_ads: usize,
    ad_lifetime: Duration,
    max_ads_per_topic: usize,
    max_ads: usize,
}

impl Ads {
    pub fn new(ad_lifetime: Duration, max_ads_per_topic: usize, max_ads: usize) -> Result<Self, &'static str> {
        let (max_ads_per_topic, max_ads) = if max_ads_per_topic <= max_ads {
            (max_ads_per_topic, max_ads)
        } else {
            return Err("Values passed to max_ads_per_topic and max_ads don't make sense");
        };

        Ok(Ads {
            expirations: VecDeque::new(),
            ads: HashMap::new(),
            total_ads: 0,
            ad_lifetime,
            max_ads_per_topic,
            max_ads,
        })
    }

    pub fn get_ad_nodes(&self, topic: Topic) -> Result<Iter<'_, Ad>, &str> {
        match self.ads.get(&topic) {
            Some(topic_ads) => Ok(topic_ads.into_iter()),
            None => Err("No ads for this topic"),
        }
    }

    pub fn ticket_wait_time(&self, topic: Topic) -> Option<Duration> {
        let now = Instant::now();
        if self.total_ads < self.max_ads {
            match self.ads.get(&topic) {
                Some(nodes) => {
                    if nodes.len() < self.max_ads_per_topic {
                        Some(Duration::from_secs(0))
                    } else {
                        match nodes.get(0) {
                            Some(ad) => {
                                let elapsed_time = now.saturating_duration_since(ad.insert_time);
                                Some(self.ad_lifetime.saturating_sub(elapsed_time))
                            }
                            None => {
                                #[cfg(debug_assertions)]
                                panic!("Panic on debug,topic key should be deleted if no ad nodes queued for it");
                                #[cfg(not(debug_assertions))]
                                {
                                    error!(
                                        "Topic key should be deleted if no ad nodes queued for it"
                                    );
                                    return None;
                                }
                            }
                        }
                    }
                }
                None => Some(Duration::from_secs(0)),
            }
        } else {
            match self.expirations.get(0) {
                Some((insert_time, _)) => {
                    let elapsed_time = now.saturating_duration_since(*insert_time);
                    Some(self.ad_lifetime.saturating_sub(elapsed_time))
                }
                None => {
                    #[cfg(debug_assertions)]
                    panic!("Panic on debug, mismatched mapping between expiration queue and total ads count");
                    #[cfg(not(debug_assertions))]
                    {
                        error!("Mismatched mapping between expiration queue and total ads count");
                        return None;
                    }
                }
            }
        }
    }

    pub fn insert(&mut self, node_record: Enr<CombinedKey>, topic: Topic) -> Result<(), &str> {
        let now = Instant::now();
        if let Some(nodes) = self.ads.get_mut(&topic) {
            if nodes.contains(&Ad::new(node_record.clone(), now)) {
                error!(
                    "This node {} is already advertising this topic",
                    node_record.node_id()
                );
                return Err("Node already advertising this topic");
            }
            nodes.push_back(Ad {
                node_record,
                insert_time: now,
            });
        } else {
            let mut nodes = VecDeque::new();
            nodes.push_back(Ad {
                node_record,
                insert_time: now,
            });
            self.ads.insert(topic, nodes);
        }
        self.expirations.push_back((now, topic));
        self.total_ads += 1;
        Ok(())
    }
}

impl Stream for Ads {
    // type returned can be unit type but for testing easier to get values, worth the overhead to keep?
    type Item = Result<((Enr<CombinedKey>, Instant), Topic), String>;
    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (insert_time, topic) = match self.expirations.get_mut(0) {
            Some((insert_time, topic)) => (insert_time, *topic),
            None => {
                debug!("No ads in 'table'");
                return Poll::Pending;
            }
        };

        if insert_time.elapsed() < self.ad_lifetime {
            return Poll::Pending;
        }

        match self.ads.get_mut(&topic) {
            Some(topic_ads) => {
                match topic_ads.pop_front() {
                    Some(ad) => {
                        if topic_ads.is_empty() {
                            self.ads.remove(&topic);
                        }
                        self.total_ads -= 1;
                        self.expirations.remove(0);
                        return Poll::Ready(Some(Ok(((ad.node_record, ad.insert_time), topic))));
                    }
                    None => {
                        #[cfg(debug_assertions)]
                        panic!("Panic on debug, topic key should be deleted if no ad nodes queued for it");
                        #[cfg(not(debug_assertions))]
                        {
                            error!("Topic key should be deleted if no ad nodes queued for it");
                            return Poll::Ready(Some(Err("No nodes for topic".into())));
                        }
                    }
                }
            }
            None => {
                #[cfg(debug_assertions)]
                panic!(
                    "Panic on debug, mismatched mapping between expiration queue and entry queue"
                );
                #[cfg(not(debug_assertions))]
                {
                    error!("Mismatched mapping between expiration queue and entry queue");
                    return Poll::Ready(Some(Err("Topic doesn't exist".into())));
                }
            }
        }
    }
}
