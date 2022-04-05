#![cfg(test)]

use super::*;
use enr::{CombinedKey, EnrBuilder};
use std::net::IpAddr;

#[tokio::test]
async fn insert_ads() {
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

    assert_eq!(ads.insert(enr.clone(), topic).map_err(|e| e), Err("Node already advertising this topic".into()));

    ads.insert(enr_2.clone(), topic).unwrap();
    ads.insert(enr.clone(), topic_2).unwrap();

    let nodes = ads.get_ad_nodes(topic).unwrap_or(vec![]);
    let nodes_topic_2 = ads.get_ad_nodes(topic_2).unwrap_or(vec![]);

    assert_eq!(nodes, vec![enr.clone(), enr_2]);
    assert_eq!(nodes_topic_2, vec![enr]);
}
