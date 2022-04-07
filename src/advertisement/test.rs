#![cfg(test)]

use super::*;
use enr::{CombinedKey, EnrBuilder};
use more_asserts::{assert_gt, assert_lt};
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

    let mut ads = Ads::new(Duration::from_secs(60), 10, 50);

    let topic = [1; 32];
    let topic_2 = [2; 32];

    ads.insert(enr.clone(), topic).unwrap();

    // Since 60 seconds haven't passed
    assert_eq!(
        ads.insert(enr.clone(), topic).map_err(|e| e),
        Err("Node already advertising this topic".into())
    );

    ads.insert(enr_2.clone(), topic).unwrap();
    ads.insert(enr.clone(), topic_2).unwrap();

    let nodes = ads.get_ad_nodes(topic).unwrap_or(vec![]);
    let nodes_topic_2 = ads.get_ad_nodes(topic_2).unwrap_or(vec![]);

    assert_eq!(nodes, vec![enr.clone(), enr_2]);
    assert_eq!(nodes_topic_2, vec![enr]);
}

#[tokio::test]
async fn ticket_wait_time_no_wait_time() {
    let ads = Ads::new(Duration::from_secs(1), 10, 50);
    let topic = [1; 32];
    let wait_time = ads.ticket_wait_time(topic);
    assert_eq!(wait_time, Ok(Duration::from_secs(0)))
}

#[tokio::test]
async fn ticket_wait_time() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let port = 5000;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr_2 = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(2), 2, 50);

    let topic = [1; 32];

    ads.insert(enr, topic).unwrap();
    assert_eq!(ads.ticket_wait_time(topic), Ok(Duration::from_secs(0)));

    ads.insert(enr_2, topic).unwrap();
    assert_gt!(ads.ticket_wait_time(topic), Ok(Duration::from_secs(1)));
    assert_lt!(ads.ticket_wait_time(topic), Ok(Duration::from_secs(2)));

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(ads.ticket_wait_time(topic), Ok(Duration::from_secs(0)));
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

    let mut ads = Ads::new(Duration::from_secs(1), 10, 50);

    let topic_1 = [1; 32];
    let topic_2 = [2; 32];

    ads.insert(enr.clone(), topic_1).unwrap();
    ads.insert(enr_2, topic_1).unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;
    ads.insert(enr.clone(), topic_2).unwrap();

    let mut expired_ads = Vec::new();

    let mut interval = tokio::time::interval(Duration::from_secs(1));

    for _ in 0..10 {
        tokio::select! {
            Some(Ok((_, topic))) = ads.next() => {
                expired_ads.push(topic);
                if topic == topic_2 {
                    // Since (enr, topic_1) should have expired, inserting it anew should be possible
                    ads.insert(enr.clone(), topic_1).unwrap();
                }
            }
            _ = interval.tick() => {}
        }
    }

    assert_eq!(expired_ads, vec![topic_1, topic_1, topic_2, topic_1])
}
