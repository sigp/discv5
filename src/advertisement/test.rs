#![cfg(test)]

use super::*;
use enr::{CombinedKey, EnrBuilder};
use std::net::IpAddr;

#[tokio::test]
async fn insert_ad_and_get_nodes() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let port = 5000;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(60));

    let topic = [1;32];
    let topic_2 = [2;32];

    ads.insert(enr.clone(), topic).unwrap();

    // Since 60 seconds haven't passed
    assert_eq!(ads.insert(enr.clone(), topic).map_err(|e| e), Err("Node already advertising this topic".into()));

    ads.insert(enr_2.clone(), topic).unwrap();
    ads.insert(enr.clone(), topic_2).unwrap();

    let nodes = ads.get_ad_nodes(topic).unwrap_or(vec![]);
    let nodes_topic_2 = ads.get_ad_nodes(topic_2).unwrap_or(vec![]);

    assert_eq!(nodes, vec![enr.clone(), enr_2]);
    assert_eq!(nodes_topic_2, vec![enr]);
}

#[tokio::test]
async fn poll_ads() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let port = 5000;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(1));

    let topic_1 = [1;32];
    let topic_2 = [2;32];

    ads.insert(enr.clone(), topic_1).unwrap();
    ads.insert(enr_2, topic_1).unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;
    ads.insert(enr.clone(), topic_2).unwrap();

    let mut expired_ads = Vec::new();

    for _ in 0..4 {
        tokio::select! {
            Some(Ok((_, topic))) = ads.next() => {
                expired_ads.push(topic);
                if topic == topic_2 {
                    // Since (enr, topic_1) should have expired, inserting it anew should be possible
                    ads.insert(enr.clone(), topic_1).unwrap();
                }
            }
        }
    }

    assert_eq!(expired_ads, vec![topic_1, topic_1, topic_2, topic_1])
}