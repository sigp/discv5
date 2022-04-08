#![cfg(test)]

use super::*;
use enr::{CombinedKey, EnrBuilder};
use more_asserts::{assert_gt, assert_lt};
use std::net::IpAddr;

#[tokio::test]
async fn insert_same_node() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(2), 10, 50).unwrap();

    let topic = [1; 32];

    ads.insert(enr.clone(), topic).unwrap();

    // Since 2 seconds haven't passed
    assert_eq!(
        ads.insert(enr.clone(), topic).map_err(|e| e),
        Err("Node already advertising this topic".into())
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
    let enr = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let port = 5000;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(2), 10, 50).unwrap();

    let topic = [1; 32];
    let topic_2 = [2; 32];

    ads.insert(enr.clone(), topic).unwrap();

    // Since 2 seconds haven't passed
    assert_eq!(
        ads.insert(enr.clone(), topic).map_err(|e| e),
        Err("Node already advertising this topic".into())
    );

    ads.insert(enr_2.clone(), topic).unwrap();
    ads.insert(enr.clone(), topic_2).unwrap();

    let nodes: Vec<Enr> = ads
        .get_ad_nodes(topic)
        .unwrap()
        .map(|ad| ad.node_record().clone())
        .collect();
    let nodes_topic_2: Vec<Enr> = ads
        .get_ad_nodes(topic_2)
        .unwrap()
        .map(|ad| ad.node_record().clone())
        .collect();

    assert_eq!(nodes, vec![enr.clone(), enr_2]);
    assert_eq!(nodes_topic_2, vec![enr]);
}

#[tokio::test]
async fn ticket_wait_time_no_wait_time() {
    let mut ads = Ads::new(Duration::from_secs(1), 10, 50).unwrap();
    let topic = [1; 32];
    let wait_time = ads.ticket_wait_time(topic);
    assert_eq!(wait_time, Some(Duration::from_secs(0)))
}

#[tokio::test]
async fn ticket_wait_time_full_table() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let port = 5000;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(3), 2, 3).unwrap();

    let topic = [1; 32];
    let topic_2 = [2; 32];

    // Add 2 ads for topic
    ads.insert(enr.clone(), topic).unwrap();
    ads.insert(enr_2.clone(), topic).unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Add an ad for topic_2
    ads.insert(enr.clone(), topic_2).unwrap();

    // Now max_ads in table is reached so the second ad for topic_2 has to wait
    assert_ne!(ads.ticket_wait_time(topic_2), None);

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Now the first ads have expired and the table is not full so no neither topic
    // or topic_2 ads have to wait
    assert_eq!(ads.ticket_wait_time(topic), None);
    assert_eq!(ads.ticket_wait_time(topic_2), None);
}

#[tokio::test]
async fn ticket_wait_time_full_topic() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let port = 5000;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(3), 2, 4).unwrap();

    let topic = [1; 32];
    let topic_2 = [2; 32];

    ads.insert(enr.clone(), topic).unwrap();
    ads.insert(enr_2.clone(), topic).unwrap();

    // Now max_ads_per_topic is reached for topic
    assert_gt!(ads.ticket_wait_time(topic), Some(Duration::from_secs(2)));
    assert_lt!(ads.ticket_wait_time(topic), Some(Duration::from_secs(3)));

    ads.insert(enr, topic_2).unwrap();

    // The table isn't full so we can insert more ads for topic_2
    assert_eq!(ads.ticket_wait_time(topic_2), None);

    // But not for topic until an ad for topic expires
    //assert_gt!(ads.ticket_wait_time(topic), Some(Duration::from_secs(2)));
    //assert_lt!(ads.ticket_wait_time(topic), Some(Duration::from_secs(3)));
    assert_ne!(ads.ticket_wait_time(topic), None);

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(ads.ticket_wait_time(topic), None);
}
