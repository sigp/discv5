#![cfg(test)]

use super::*;
use crate::advertisement::topic::Sha256Topic as Topic;
use enr::{CombinedKey, EnrBuilder};
use more_asserts::{assert_gt, assert_lt};
use std::net::IpAddr;

#[tokio::test]
async fn insert_same_node() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(2), 10, 50, 100, 100).unwrap();

    let topic = Topic::new(std::str::from_utf8(&[1u8; 32]).unwrap()).hash();

    ads.insert(enr.clone(), topic).unwrap();

    // Since 2 seconds haven't passed
    assert_eq!(
        ads.insert(enr.clone(), topic).map_err(|e| e),
        Err("Node already advertising this topic")
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    ads.insert(enr.clone(), topic).unwrap();
}

#[tokio::test]
async fn insert_ad_and_get_nodes() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();

    let port = 5000;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(2), 10, 50, 100, 100).unwrap();

    let topic = Topic::new(std::str::from_utf8(&[1u8; 32]).unwrap()).hash();
    let topic_2 = Topic::new(std::str::from_utf8(&[2u8; 32]).unwrap()).hash();

    // Add an ad for topic from enr
    ads.insert(enr.clone(), topic).unwrap();

    // The ad hasn't expired and duplicates are not allowed
    assert_eq!(
        ads.insert(enr.clone(), topic).map_err(|e| e),
        Err("Node already advertising this topic")
    );

    // Add an ad for topic from enr_2
    ads.insert(enr_2.clone(), topic).unwrap();

    // Add an ad for topic_2 from enr
    ads.insert(enr.clone(), topic_2).unwrap();

    let nodes: Vec<&Enr> = ads
        .get_ad_nodes(topic)
        .map(|ad_node| ad_node.node_record())
        .collect();

    let nodes_topic_2: Vec<&Enr> = ads
        .get_ad_nodes(topic_2)
        .map(|ad_node| ad_node.node_record())
        .collect();

    assert_eq!(nodes, vec![&enr, &enr_2]);
    assert_eq!(nodes_topic_2, vec![&enr]);
}

#[tokio::test]
async fn ticket_wait_time_no_wait_time() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();
    let mut ads = Ads::new(Duration::from_secs(1), 10, 50, 100, 100).unwrap();
    let topic = Topic::new(std::str::from_utf8(&[1u8; 32]).unwrap()).hash();
    assert_eq!(ads.ticket_wait_time(topic, enr.node_id(), ip), None)
}

#[tokio::test]
async fn ticket_wait_time_duration() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(3), 1, 3, 100, 100).unwrap();

    let topic = Topic::new(std::str::from_utf8(&[1u8; 32]).unwrap()).hash();

    // Add an add for topic
    ads.insert(enr.clone(), topic).unwrap();

    assert_gt!(
        ads.ticket_wait_time(topic, enr.node_id(), ip),
        Some(Duration::from_secs(2))
    );
    assert_lt!(
        ads.ticket_wait_time(topic, enr.node_id(), ip),
        Some(Duration::from_secs(3))
    );
}

#[tokio::test]
async fn ticket_wait_time_full_table() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();

    let port_2 = 5000;
    let ip_2: IpAddr = "192.168.0.1".parse().unwrap();
    let key_2 = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4")
        .ip(ip_2)
        .udp4(port_2)
        .build(&key_2)
        .unwrap();

    let mut ads = Ads::new(Duration::from_secs(3), 2, 3, 100, 100).unwrap();

    let topic = Topic::new(std::str::from_utf8(&[1u8; 32]).unwrap()).hash();
    let topic_2 = Topic::new(std::str::from_utf8(&[2u8; 32]).unwrap()).hash();

    // Add 2 ads for topic
    ads.insert(enr.clone(), topic).unwrap();
    ads.insert(enr_2.clone(), topic).unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Add an ad for topic_2
    ads.insert(enr.clone(), topic_2).unwrap();

    // Now max_ads in table is reached so the second ad for topic_2 has to wait
    assert_ne!(ads.ticket_wait_time(topic_2, enr.node_id(), ip), None);

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Now the first ads have expired and the table is not full so no neither topic
    // or topic_2 ads have to wait
    assert_eq!(ads.ticket_wait_time(topic, enr.node_id(), ip), None);
    assert_eq!(ads.ticket_wait_time(topic_2, enr_2.node_id(), ip_2), None);
}

#[tokio::test]
async fn ticket_wait_time_full_topic() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();

    let port_2 = 5000;
    let ip_2: IpAddr = "192.168.0.1".parse().unwrap();
    let key_2 = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4")
        .ip(ip_2)
        .udp4(port_2)
        .build(&key_2)
        .unwrap();

    let port_3 = 5000;
    let ip_3: IpAddr = "8.8.8.8".parse().unwrap();
    let key_3 = CombinedKey::generate_secp256k1();
    let enr_3 = EnrBuilder::new("v4")
        .ip(ip_3)
        .udp4(port_3)
        .build(&key_3)
        .unwrap();

    let mut ads = Ads::new(Duration::from_secs(3), 2, 4, 100, 100).unwrap();

    let topic = Topic::new(std::str::from_utf8(&[1u8; 32]).unwrap()).hash();
    let topic_2 = Topic::new(std::str::from_utf8(&[2u8; 32]).unwrap()).hash();

    // Add 2 ads for topic
    ads.insert(enr.clone(), topic).unwrap();
    ads.insert(enr_2.clone(), topic).unwrap();

    // Now max_ads_per_topic is reached for topic
    assert_ne!(ads.ticket_wait_time(topic, enr_3.node_id(), ip_3), None);

    // Add a topic_2 ad
    ads.insert(enr.clone(), topic_2).unwrap();

    // The table isn't full so topic_2 ads don't have to wait
    assert_eq!(ads.ticket_wait_time(topic_2, enr_2.node_id(), ip_2), None);

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(ads.ticket_wait_time(topic, enr_3.node_id(), ip), None);
}
