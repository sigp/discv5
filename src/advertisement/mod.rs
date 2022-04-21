use super::*;
use crate::Enr;
use core::time::Duration;
use futures::prelude::*;
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::Instant;
pub use topic::TopicHash;
use tracing::{debug, error};

mod test;
pub mod ticket;
pub mod topic;

#[derive(Debug)]
pub struct AdNode {
    node_record: Enr,
    insert_time: Instant,
}

impl AdNode {
    pub fn new(node_record: Enr, insert_time: Instant) -> Self {
        AdNode {
            node_record,
            insert_time,
        }
    }
}

impl PartialEq for AdNode {
    fn eq(&self, other: &Self) -> bool {
        self.node_record == other.node_record
    }
}

struct AdTopic {
    topic: TopicHash,
    insert_time: Instant,
}

impl AdTopic {
    pub fn new(topic: TopicHash, insert_time: Instant) -> Self {
        AdTopic { topic, insert_time }
    }
}

pub struct Ads {
    expirations: VecDeque<AdTopic>,
    ads: HashMap<TopicHash, VecDeque<AdNode>>,
    ad_lifetime: Duration,
    max_ads_per_topic: usize,
    max_ads: usize,
}

impl Ads {
    pub fn new(
        ad_lifetime: Duration,
        max_ads_per_topic: usize,
        max_ads: usize,
    ) -> Result<Self, &'static str> {
        if max_ads_per_topic > max_ads {
            return Err("Ads per topic cannot be > max_ads");
        }

        Ok(Ads {
            expirations: VecDeque::new(),
            ads: HashMap::new(),
            ad_lifetime,
            max_ads_per_topic,
            max_ads,
        })
    }

    pub fn get_ad_nodes(&self, topic: TopicHash) -> impl Iterator<Item = Enr> + '_ {
        self.ads
            .get(&topic)
            .into_iter()
            .flat_map(|nodes| nodes.iter())
            .map(|node| node.node_record.clone())
    }

    pub fn ticket_wait_time(&mut self, topic: TopicHash) -> Option<Duration> {
        self.remove_expired();
        let now = Instant::now();
        if self.expirations.len() < self.max_ads {
            self.ads
                .get(&topic)
                .filter(|nodes| nodes.len() >= self.max_ads_per_topic)
                .map(|nodes| {
                    nodes.get(0).map(|ad| {
                        let elapsed_time = now.saturating_duration_since(ad.insert_time);
                        self.ad_lifetime.saturating_sub(elapsed_time)
                    })
                })
                .unwrap_or_default()
        } else {
            self.expirations.get(0).map(|ad| {
                let elapsed_time = now.saturating_duration_since(ad.insert_time);
                self.ad_lifetime.saturating_sub(elapsed_time)
            })
        }
    }

    fn remove_expired(&mut self) {
        let mut map: HashMap<TopicHash, usize> = HashMap::new();

        self.expirations
            .iter()
            .take_while(|ad| ad.insert_time.elapsed() >= self.ad_lifetime)
            .for_each(|ad| {
                let count = map.entry(ad.topic).or_default();
                *count += 1;
            });

        map.into_iter().for_each(|(topic, index)| {
            let entry_ref = self.ads.entry(topic).or_default();
            for _ in 0..index {
                entry_ref.pop_front();
                self.expirations.pop_front();
            }
            if entry_ref.is_empty() {
                self.ads.remove(&topic);
            }
        });
    }

    pub fn insert(&mut self, node_record: Enr, topic: TopicHash) -> Result<(), &str> {
        self.remove_expired();
        let now = Instant::now();
        let nodes = self.ads.entry(topic).or_default();
        if nodes.contains(&AdNode::new(node_record.clone(), now)) {
            error!(
                "This node {} is already advertising this topic",
                node_record.node_id()
            );
            return Err("Node already advertising this topic");
        }
        nodes.push_back(AdNode {
            node_record,
            insert_time: now,
        });
        self.expirations.push_back(AdTopic::new(topic, now));
        Ok(())
    }
}
