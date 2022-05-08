use super::*;
use crate::Enr;
use core::time::Duration;
use futures::prelude::*;
use more_asserts::debug_unreachable;
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::Instant;
use topic::TopicHash;
use tracing::{debug, error};

mod test;
pub mod ticket;
pub mod topic;

/// An AdNode is a node that occupies an ad slot on another node.
#[derive(Debug, Clone)]
pub struct AdNode {
    /// The node being advertised.
    node_record: Enr,
    /// The insert_time is used to retrieve the ticket_wait time for a given
    /// topic.
    insert_time: Instant,
}

impl AdNode {
    pub fn new(node_record: Enr, insert_time: Instant) -> Self {
        AdNode {
            node_record,
            insert_time,
        }
    }

    pub fn node_record(&self) -> &Enr {
        &self.node_record
    }
}

impl PartialEq for AdNode {
    fn eq(&self, other: &Self) -> bool {
        self.node_record == other.node_record
    }
}

/// An AdTopic keeps track of when an AdNode is created.
#[derive(Clone, Debug)]
struct AdTopic {
    /// The topic maps to the topic of an AdNode in Ads's ads.
    topic: TopicHash,
    /// The insert_time is used to make sure and AdNode persists in Ads
    /// only the ad_lifetime duration.
    insert_time: Instant,
}

impl AdTopic {
    pub fn new(topic: TopicHash, insert_time: Instant) -> Self {
        AdTopic { topic, insert_time }
    }
}

/// The Ads struct contains the locally adveritsed AdNodes.
#[derive(Clone, Debug)]
pub struct Ads {
    /// The expirations makes sure that AdNodes are advertised only for the
    /// ad_lifetime duration.
    expirations: VecDeque<AdTopic>,
    /// The ads store the AdNodes per TopicHash in FIFO order of expiration.
    ads: HashMap<TopicHash, VecDeque<AdNode>>,
    /// The ad_lifetime is specified by the spec but can be modified for
    /// testing purposes.
    ad_lifetime: Duration,
    /// The max_ads_per_topic limit is up to the user although recommnedations
    /// are given in the specs.
    max_ads_per_topic: usize,
    /// The max_ads limit is up to the user although recommnedations are
    /// given in the specs.
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

    pub fn get_ad_nodes(&self, topic: TopicHash) -> impl Iterator<Item = &AdNode> + '_ {
        self.ads.get(&topic).into_iter().flatten()
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
        let mut to_remove_ads: HashMap<TopicHash, usize> = HashMap::new();

        self.expirations
            .iter()
            .take_while(|ad| ad.insert_time.elapsed() >= self.ad_lifetime)
            .for_each(|ad| {
                *to_remove_ads.entry(ad.topic).or_default() += 1;
            });

        to_remove_ads.into_iter().for_each(|(topic, index)| {
            if let Some(topic_ads) = self.ads.get_mut(&topic) {
                for _ in 0..index {
                    topic_ads.pop_front();
                    self.expirations.pop_front();
                }
                if topic_ads.is_empty() {
                    self.ads.remove(&topic);
                }
            } else {
                debug_unreachable!("Mismatched mapping between ads and their expirations");
            }
        });
    }

    pub fn insert(&mut self, node_record: Enr, topic: TopicHash) -> Result<(), &str> {
        self.remove_expired();
        let now = Instant::now();
        let nodes = self.ads.entry(topic).or_default();
        let ad_node = AdNode::new(node_record, now);
        if nodes.contains(&ad_node) {
            error!(
                "This node {} is already advertising this topic",
                ad_node.node_record().node_id()
            );
            return Err("Node already advertising this topic");
        }
        nodes.push_back(ad_node);
        self.expirations.push_back(AdTopic::new(topic, now));
        Ok(())
    }
}

impl fmt::Display for Ads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ads = self
            .ads
            .iter()
            .map(|ad| {
                let ad_node_ids =
                    ad.1.iter()
                        .map(|ad_node| base64::encode(ad_node.node_record.node_id().raw()))
                        .collect::<Vec<String>>();
                format!("Topic: {}, Advertised at: {:?}", ad.0, ad_node_ids)
            })
            .collect::<Vec<String>>();
        write!(f, "{:?}", ads)
    }
}
