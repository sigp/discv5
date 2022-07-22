use super::*;
use crate::{enr::NodeId, Enr};
use core::time::Duration;
use futures::prelude::*;
use more_asserts::debug_unreachable;
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::Instant;
use topic::TopicHash;
use tracing::{debug, error};

mod test;
pub mod ticket;
pub mod topic;

/// The max nodes to adveritse for a topic.
const MAX_ADS_TOPIC: usize = 100;

/// The max nodes to advertise.
const MAX_ADS: usize = 50000;

/// The max ads per subnet per topic.
const MAX_ADS_SUBNET_TOPIC: usize = 5;

/// The max ads per subnet.
const MAX_ADS_SUBNET: usize = 50;

/// The time after a REGCONFIRMATION is sent that an ad is placed.
pub const AD_LIFETIME: Duration = Duration::from_secs(60 * 15);

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

/// The Ads struct contains adveritsed AdNodes. Topics table is used to refer to
/// all the ads, and the table stores ads by topic.
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
    max_ads_topic: usize,
    /// The max_ads limit is up to the user although recommnedations are
    /// given in the specs.
    max_ads: usize,
    /// Max ads per subnet for the whole table,
    max_ads_subnet: usize,
    /// Max ads per subnet per topic,
    max_ads_subnet_topic: usize,
    /// Expiration times of ads by subnet
    subnet_expirations: HashMap<Vec<u8>, VecDeque<Instant>>,
}

impl Ads {
    pub fn new(
        ad_lifetime: Duration,
        max_ads_topic: usize,
        max_ads: usize,
        max_ads_subnet: usize,
        max_ads_subnet_topic: usize,
    ) -> Self {
        let (max_ads_topic, max_ads, max_ads_subnet, max_ads_subnet_topic) =
            if max_ads_topic > max_ads || max_ads_subnet_topic > max_ads_subnet {
                error!(
                "Ads per topic [per subnet] cannot be > max_ads [per subnet]. Using default values"
            );
                return Self::default();
            } else {
                (max_ads_topic, max_ads, max_ads_subnet, max_ads_subnet_topic)
            };

        Ads {
            expirations: VecDeque::new(),
            ads: HashMap::new(),
            ad_lifetime,
            max_ads_topic,
            max_ads,
            max_ads_subnet,
            max_ads_subnet_topic,
            subnet_expirations: HashMap::new(),
        }
    }

    pub fn default() -> Self {
        Ads::new(
            AD_LIFETIME,
            MAX_ADS_TOPIC,
            MAX_ADS,
            MAX_ADS_SUBNET,
            MAX_ADS_SUBNET_TOPIC,
        )
    }

    /// Checks if there are currently any entries in the topics table.
    pub fn is_empty(&self) -> bool {
        self.expirations.is_empty()
    }

    /// Returns the amount of ads currently in the topics table.
    pub fn len(&self) -> usize {
        self.expirations.len()
    }

    /// Returns an iterator over the ads currently in the topics table for a given topic
    /// if any.
    pub fn get_ad_nodes(&self, topic: TopicHash) -> impl Iterator<Item = &AdNode> + '_ {
        self.ads.get(&topic).into_iter().flatten()
    }

    /// Ticket wait time enforces diversity among adveritsed nodes. The ticket wait time is
    /// calculated after removing expired entries based on the current state of the topics
    /// table (ads).
    pub fn ticket_wait_time(
        &mut self,
        topic: TopicHash,
        node_id: NodeId,
        ip: IpAddr,
    ) -> Option<Duration> {
        self.remove_expired();
        let now = Instant::now();
        // Occupancy check to see if the table is full.
        // Similarity check to see if the ad slots for an ip subnet are full.
        let subnet = match ip {
            IpAddr::V4(ip) => ip.octets()[0..=2].to_vec(),
            IpAddr::V6(ip) => ip.octets()[0..=5].to_vec(),
        };

        let wait_time_max_ads_subnet =
            if let Some(expirations) = self.subnet_expirations.get_mut(&subnet) {
                if expirations.len() >= self.max_ads_subnet {
                    expirations.pop_front().map(|insert_time| {
                        let elapsed_time = now.saturating_duration_since(insert_time);
                        self.ad_lifetime.saturating_sub(elapsed_time)
                    })
                } else {
                    None
                }
            } else {
                None
            };

        if let Some(nodes) = self.ads.get(&topic) {
            let mut subnet_first_insert_time = None;
            let mut subnet_ads_count = 0;
            for ad in nodes.iter() {
                // Similarity check to see if ads with same node id and ip exist for the given topic.
                let same_ip = match ip {
                    IpAddr::V4(ip) => ad.node_record.ip4() == Some(ip),
                    IpAddr::V6(ip) => ad.node_record.ip6() == Some(ip),
                };
                if ad.node_record.node_id() == node_id || same_ip {
                    let elapsed_time = now.saturating_duration_since(ad.insert_time);
                    let wait_time = self.ad_lifetime.saturating_sub(elapsed_time);
                    return Some(wait_time);
                }
                let subnet_match = match ip {
                    IpAddr::V4(_) => ad
                        .node_record
                        .ip4()
                        .map(|ip| ip.octets()[0..=2].to_vec() == subnet)
                        .unwrap_or(false),
                    IpAddr::V6(_) => ad
                        .node_record
                        .ip6()
                        .map(|ip| ip.octets()[0..=5].to_vec() == subnet)
                        .unwrap_or(false),
                };
                if subnet_match {
                    if subnet_first_insert_time.is_none() {
                        subnet_first_insert_time = Some(ad.insert_time);
                    }
                    subnet_ads_count += 1;
                }
            }
            // Similarity check to see if the limit of ads per subnet per topic or otherwise table is reached.
            // If the ad slots per subnet per topic are not full and neither are the ad slots per subnet for
            // the whole table then waiting time is not decided by subnet but by the number of free ad slots
            // for the topic.
            if subnet_ads_count >= self.max_ads_subnet_topic {
                if let Some(insert_time) = subnet_first_insert_time {
                    let elapsed_time = now.saturating_duration_since(insert_time);
                    let wait_time = self.ad_lifetime.saturating_sub(elapsed_time);
                    return Some(wait_time);
                }
            }
            if wait_time_max_ads_subnet.is_some() {
                return wait_time_max_ads_subnet;
            }

            // Occupancy check to see if the ad slots for a certain topic are full.
            if nodes.len() >= self.max_ads_topic {
                return nodes.front().map(|ad| {
                    let elapsed_time = now.saturating_duration_since(ad.insert_time);
                    self.ad_lifetime.saturating_sub(elapsed_time)
                });
            }
        }
        // Similarity check to see if the limit of ads per subnet per table is reached.
        if wait_time_max_ads_subnet.is_some() {
            return wait_time_max_ads_subnet;
        }
        // If the ad slots per topic are not full and neither is the table then waiting time is None,
        // otherwise waiting time is that of the next ad in the table to expire.
        if self.expirations.len() < self.max_ads {
            None
        } else {
            self.expirations.front().map(|ad| {
                let elapsed_time = now.saturating_duration_since(ad.insert_time);
                self.ad_lifetime.saturating_sub(elapsed_time)
            })
        }
    }

    /// Removes ads that have been in the topics table for at least the ad lifetime specified in [`Ads`].
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
                for i in 0..index {
                    let ad = topic_ads.pop_front();
                    if let Some(ad) = ad {
                        let subnet = if let Some(ip) = ad.node_record.ip4() {
                            Some(ip.octets()[0..=2].to_vec())
                        } else {
                            ad.node_record.ip6().map(|ip6| ip6.octets()[0..=5].to_vec())
                        };
                        if let Some(subnet) = subnet {
                            if let Some(subnet_expiries) = self.subnet_expirations.get_mut(&subnet) {
                                subnet_expiries.pop_front();
                            } else {
                                debug_unreachable!("Mismatched mapping between ads and their expirations by subnet. At least {} ads should exist for subnet {:?}", i+1, subnet);
                            }
                        }
                    } else {
                        debug_unreachable!("Mismatched mapping between ads and their expirations. At least {} ads should exist for topic hash {}", i+1, topic)
                    }
                    self.expirations.pop_front();
                }
                if topic_ads.is_empty() {
                    self.ads.remove(&topic);
                }

            } else {
                debug_unreachable!("Mismatched mapping between ads and their expirations. An entry should exist for topic hash {}", topic);
            }
        });
    }

    /// Inserts a unique node record - topic mapping into the topics table after removing expired entries.
    pub fn insert(
        &mut self,
        node_record: Enr,
        topic: TopicHash,
        ip: IpAddr,
    ) -> Result<(), (Duration, &str)> {
        if let Some(wait_time) = self.ticket_wait_time(topic, node_record.node_id(), ip) {
            return Err((wait_time, "There is currently no ad slot free for this node - topic combination. Discarding registration attempt."));
        }
        self.remove_expired();
        let now = Instant::now();

        let subnet = if let Some(ip) = node_record.ip4() {
            Some(ip.octets()[0..=2].to_vec())
        } else {
            node_record.ip6().map(|ip6| ip6.octets()[0..=5].to_vec())
        };
        if let Some(subnet) = subnet {
            let subnet_expirires = self
                .subnet_expirations
                .entry(subnet)
                .or_insert_with(VecDeque::new);
            subnet_expirires.push_back(now);
        }
        let nodes = self.ads.entry(topic).or_default();

        let ad_node = AdNode::new(node_record, now);
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
