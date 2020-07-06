#![cfg(test)]

use crate::kbucket;
use crate::Discv5;
use crate::*;
use enr::NodeId;
use enr::{CombinedKey, Enr, EnrBuilder, EnrKey};
use env_logger;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift;
use std::net::Ipv4Addr;
use std::{collections::HashMap, net::IpAddr};

// #[tokio::test]
// async fn test_updating_connection_on_ping() {
//     let enr_key1 = CombinedKey::generate_secp256k1();
//     let ip: IpAddr = "127.0.0.1".parse().unwrap();
//     let config = Discv5Config::default();
//     let enr = EnrBuilder::new("v4")
//         .ip(ip.clone().into())
//         .udp(10001)
//         .build(&enr_key1)
//         .unwrap();
//     let ip2: IpAddr = "127.0.0.1".parse().unwrap();
//     let enr_key2 = CombinedKey::generate_secp256k1();
//     let enr2 = EnrBuilder::new("v4")
//         .ip(ip2.clone().into())
//         .udp(10002)
//         .build(&enr_key2)
//         .unwrap();

//     // Set up discv5 with one disconnected node
//     let socket_addr = enr.udp_socket().unwrap();

//     let mut discv5 = Discv5::new(enr, enr_key1, config).unwrap();
//     discv5.start(socket_addr);
//     discv5.add_enr(enr2.clone()).unwrap();

//     assert_eq!(discv5.connected_peers(), 0);

//     // Add a fake request
//     let ping_response = Response { id: 1, body: ResponseBody::Ping {
//         enr_seq: 2,
//         ip: ip2,
//         port: 10002,
//     };
//     let ping_request = rpc::Request::Ping { enr_seq: 2 };
//     let req = RpcRequest(2, enr2.node_id().clone());
//     discv5
//         .active_rpc_requests
//         .insert(req, (Some(QueryId(1)), ping_request.clone()));

//     // Handle the ping and expect the disconnected Node to become connected
//     discv5.handle_rpc_response(enr2.node_id().clone(), 2, ping_response);
//     buckets = discv5.kbuckets.clone();

//     node = buckets.iter().next().unwrap();
//     assert_eq!(node.status, NodeStatus::Connected);
// }
