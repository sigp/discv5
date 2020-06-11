#![cfg(test)]

use crate::kbucket;
use crate::Discv5;
use crate::*;
use enr::NodeId;
use enr::{CombinedKey, Enr, EnrBuilder, EnrKey};
use env_logger;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift;
use std::{collections::HashMap, net::IpAddr};

#[tokio::test]
async fn test_updating_connection_on_ping() {
    let enr_key1 = CombinedKey::generate_secp256k1();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let config = Discv5Config::default();
    let enr = EnrBuilder::new("v4")
        .ip(ip.clone().into())
        .udp(10001)
        .build(&enr_key1)
        .unwrap();
    let ip2: IpAddr = "127.0.0.1".parse().unwrap();
    let enr_key2 = CombinedKey::generate_secp256k1();
    let enr2 = EnrBuilder::new("v4")
        .ip(ip2.clone().into())
        .udp(10002)
        .build(&enr_key2)
        .unwrap();

    // Set up discv5 with one disconnected node
    let socket_addr = enr.udp_socket().unwrap();
    let mut discv5 = Discv5::new(enr, enr_key1, config).unwrap();
    discv5.start(socket_addr);
    discv5.add_enr(enr2.clone()).unwrap();

    assert_eq!(discv5.connected_peers(), 0);

    // Add a fake request
    let ping_response = Response { id: 1, body: ResponseBody::Ping {
        enr_seq: 2,
        ip: ip2,
        port: 10002,
    };
    let ping_request = rpc::Request::Ping { enr_seq: 2 };
    let req = RpcRequest(2, enr2.node_id().clone());
    discv5
        .active_rpc_requests
        .insert(req, (Some(QueryId(1)), ping_request.clone()));

    // Handle the ping and expect the disconnected Node to become connected
    discv5.handle_rpc_response(enr2.node_id().clone(), 2, ping_response);
    buckets = discv5.kbuckets.clone();

    node = buckets.iter().next().unwrap();
    assert_eq!(node.status, NodeStatus::Connected);
}

// The kbuckets table can have maximum 10 nodes in the same /24 subnet across all buckets
#[tokio::test]
async fn test_table_limits() {
    // this seed generates 12 node id's that are distributed accross buckets such that no more than
    // 2 exist in a single bucket.
    let mut keypairs = generate_deterministic_keypair(12, 9487);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let enr_key: CombinedKey = keypairs.remove(0);
    let config = Discv5ConfigBuilder::new().ip_limit(true).build();
    let enr = EnrBuilder::new("v4")
        .ip(ip.clone().into())
        .udp(9050)
        .build(&enr_key)
        .unwrap();

    let socket_addr = enr.udp_socket().unwrap();
    let mut discv5: Discv5 = Discv5::new(enr, enr_key, config, socket_addr).unwrap();
    let table_limit: usize = 10;
    // Generate `table_limit + 2` nodes in the same subnet.
    let enrs: Vec<Enr<CombinedKey>> = (1..=table_limit + 1)
        .map(|i| {
            let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
            let enr_key: CombinedKey = keypairs.remove(0);
            EnrBuilder::new("v4")
                .ip(ip.clone().into())
                .udp(9050 + i as u16)
                .build(&enr_key)
                .unwrap()
        })
        .collect();
    for enr in enrs {
        discv5.add_enr(enr.clone()).unwrap();
    }
    // Number of entries should be `table_limit`, i.e one node got restricted
    assert_eq!(
        discv5.kbuckets_entries().collect::<Vec<_>>().len(),
        table_limit
    );
}

// Each bucket can have maximum 2 nodes in the same /24 subnet
#[tokio::test]
async fn test_bucket_limits() {
    let enr_key = CombinedKey::generate_secp256k1();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let enr = EnrBuilder::new("v4")
        .ip(ip.clone().into())
        .udp(9500)
        .build(&enr_key)
        .unwrap();
    let bucket_limit: usize = 2;
    // Generate `bucket_limit + 1` keypairs that go in `enr` node's 256th bucket.
    let keys = {
        let mut keys = Vec::new();
        for _ in 0..bucket_limit + 1 {
            loop {
                let key = CombinedKey::generate_secp256k1();
                let enr_new = EnrBuilder::new("v4").build(&key).unwrap();
                let node_key: kbucket::Key<NodeId> = enr.node_id().clone().into();
                let distance = node_key
                    .log2_distance(&enr_new.node_id().clone().into())
                    .unwrap();
                if distance == 256 {
                    keys.push(key);
                    break;
                }
            }
        }
        keys
    };
    // Generate `bucket_limit + 1` nodes in the same subnet.
    let enrs: Vec<Enr<CombinedKey>> = (1..=bucket_limit + 1)
        .map(|i| {
            let kp = &keys[i - 1];
            let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
            EnrBuilder::new("v4")
                .ip(ip.clone().into())
                .udp(9500 + i as u16)
                .build(kp)
                .unwrap()
        })
        .collect();

    let config = Discv5ConfigBuilder::new().ip_limit(true).build();
    let socket_addr = enr.udp_socket().unwrap();
    let mut discv5 = Discv5::new(enr, enr_key, config, socket_addr).unwrap();
    for enr in enrs {
        discv5.add_enr(enr.clone()).unwrap();
    }

    // Number of entries should be equal to `bucket_limit`.
    assert_eq!(
        discv5.kbuckets_entries().collect::<Vec<_>>().len(),
        bucket_limit
    );
}
*/
