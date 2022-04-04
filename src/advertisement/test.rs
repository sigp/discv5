#![cfg(test)]

use super::*;
use enr::{CombinedKey, EnrBuilder};
use std::net::IpAddr;

#[tokio::test]
async fn insert_ad() {
    // Create the test values needed
    let port = 6666;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").ip(ip).udp(port).build(&key).unwrap();

    let mut ads = Ads::new(Duration::from_secs(60));

    let topic = [1;32];

    ads.insert(enr.clone(), topic);

    let nodes = ads.get_ad_nodes(topic).unwrap_or(vec![]);

    assert_eq!(nodes, vec![enr]);
}
