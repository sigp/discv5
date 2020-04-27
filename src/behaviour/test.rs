#![cfg(test)]

use crate::behaviour::RpcRequest;
use crate::kbucket::*;
use crate::query_pool::QueryId;
use crate::*;
use crate::{Discv5, Discv5Event};
use env_logger;
use libp2p_core::{
    identity, muxing::StreamMuxerBox, nodes::Substream, transport::boxed::Boxed,
    transport::MemoryTransport, PeerId, Transport,
};
use libp2p_swarm::Swarm;
use tokio::prelude::*;
use tokio::runtime::Runtime;

use crate::kbucket;
use enr::{CombinedKey, Enr, EnrBuilder};
use enr::{EnrKey, NodeId};
use libp2p_secio::SecioConfig;
use libp2p_yamux as yamux;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type SwarmType =
    Swarm<Boxed<(PeerId, StreamMuxerBox), io::Error>, Discv5<Substream<StreamMuxerBox>>>;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn build_swarms(n: usize, base_port: u16) -> Vec<SwarmType> {
    let mut swarms = Vec::new();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    for port in base_port..base_port + n as u16 {
        let keypair = identity::Keypair::generate_secp256k1();
        let enr_key: CombinedKey = keypair.clone().try_into().unwrap();
        let config = Discv5Config::default();

        let enr = EnrBuilder::new("v4")
            .ip(ip.clone().into())
            .udp(port)
            .build(&enr_key)
            .unwrap();
        // transport for building a swarm
        let transport = MemoryTransport::default()
            .upgrade(libp2p_core::upgrade::Version::V1)
            .authenticate(SecioConfig::new(keypair.clone()))
            .multiplex(yamux::Config::default())
            .map(|(p, m), _| (p, StreamMuxerBox::new(m)))
            .map_err(|e| panic!("Failed to create transport: {:?}", e))
            .boxed();
        let socket_addr = enr.udp_socket().unwrap();
        let discv5 = Discv5::new(enr, keypair.clone(), config, socket_addr).unwrap();
        swarms.push(Swarm::new(
            transport,
            discv5,
            keypair.public().into_peer_id(),
        ));
    }
    swarms
}

/// Build `n` swarms using passed keypairs.
fn build_swarms_from_keypairs(keys: Vec<identity::Keypair>, base_port: u16) -> Vec<SwarmType> {
    let mut swarms = Vec::new();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    // for port in base_port..base_port + keypairs.len() as u16 {
    for (i, key) in keys.into_iter().enumerate() {
        let port = base_port + i as u16;

        let enr_key: CombinedKey = key.clone().try_into().unwrap();
        let config = Discv5ConfigBuilder::new().ip_limit(false).build();

        let enr = EnrBuilder::new("v4")
            .ip(ip.clone().into())
            .udp(port)
            .build(&enr_key)
            .unwrap();

        // transport for building a swarm
        let transport = MemoryTransport::default()
            .upgrade(libp2p_core::upgrade::Version::V1)
            .authenticate(SecioConfig::new(key.clone()))
            .multiplex(yamux::Config::default())
            .map(|(p, m), _| (p, StreamMuxerBox::new(m)))
            .map_err(|e| panic!("Failed to create transport: {:?}", e))
            .boxed();
        let socket_addr = enr.udp_socket().unwrap();
        let discv5 = Discv5::new(enr, key.clone(), config, socket_addr).unwrap();
        swarms.push(Swarm::new(transport, discv5, key.public().into_peer_id()));
    }
    swarms
}

/// Generate `n` deterministic keypairs from a given seed.
fn generate_deterministic_keypair(n: usize, seed: u64) -> Vec<identity::Keypair> {
    let mut keypairs = Vec::new();
    for i in 0..n {
        let sk = {
            let rng = &mut rand_xorshift::XorShiftRng::seed_from_u64(seed + i as u64);
            let mut b = [0; secp256k1::util::SECRET_KEY_SIZE];
            loop {
                // until a value is given within the curve order
                rng.fill_bytes(&mut b);
                if let Ok(k) = identity::secp256k1::SecretKey::from_bytes(&mut b) {
                    break k;
                }
            }
        };
        let kp = identity::Keypair::Secp256k1(identity::secp256k1::Keypair::from(sk));
        keypairs.push(kp);
    }
    keypairs
}

fn get_distance(node1: &NodeId, node2: &NodeId) -> Option<u64> {
    let node1: kbucket::Key<NodeId> = node1.clone().into();
    node1.log2_distance(&node2.clone().into())
}

// Simple searching function to find seeds that give node ids for a range of testing and different
// topologies
#[allow(dead_code)]
fn find_seed_same_bucket() {
    let mut seed = 1;
    'main: loop {
        if seed % 1000 == 0 {
            println!("Seed: {}", seed);
        }

        let keys = generate_deterministic_keypair(11, seed);

        let node_ids = keys
            .into_iter()
            .map(|k| CombinedKey::try_from(k).unwrap())
            .map(|k| NodeId::from(k.public()))
            .collect::<Vec<_>>();

        let local = node_ids[0];

        for id in node_ids[1..].iter() {
            let distance = get_distance(&local, id);
            if distance != Some(256) {
                seed += 1;
                continue 'main;
            }
        }
        break;
    }
    println!("Found Seed: {}", seed);
}

#[allow(dead_code)]
fn find_seed_spread_bucket() {
    let mut buckets;
    let mut seed = 1;
    loop {
        seed += 1;

        let keys = generate_deterministic_keypair(11, seed);

        let node_ids = keys
            .into_iter()
            .map(|k| CombinedKey::try_from(k).unwrap())
            .map(|k| NodeId::from(k.public()))
            .collect::<Vec<_>>();

        let local = node_ids[0];

        buckets = HashMap::new();

        for id in node_ids[1..].iter() {
            let distance = get_distance(&local, id);
            if let Some(distance) = distance {
                *buckets.entry(distance).or_insert_with(|| 0) += 1;
            }
        }
        if buckets.values().find(|v| **v > 2) == None {
            break;
        }
        if seed % 1000 == 0 {
            println!("Seed: {}", seed);
        }
    }
    println!("Found Seed: {}", seed);
    for (k, v) in buckets.iter() {
        println!("{}, {}", k, v);
    }
}

/// Test for a star topology with `num_nodes` connected to a `bootstrap_node`
/// FINDNODE request is sent from any of the `num_nodes` nodes to a `target_node`
/// which isn't part of the swarm.
/// The seed for the keypair generation is chosen such that all `num_nodes` nodes
/// and the `target_node` are in the 256th k-bucket of the bootstrap node.
/// This ensures that all nodes are found in a single FINDNODE query.
#[test]
fn test_discovery_star_topology() {
    init();
    let total_nodes = 10;
    // Seed is chosen such that all nodes are in the 256th bucket of bootstrap
    let seed = 1652;
    // Generate `num_nodes` + bootstrap_node and target_node keypairs from given seed
    let keypairs = generate_deterministic_keypair(total_nodes + 2, seed);
    let mut swarms = build_swarms_from_keypairs(keypairs, 11000);
    // Last node is bootstrap node in a star topology
    let mut bootstrap_node = swarms.remove(0);
    // target_node is not polled.
    let target_node = swarms.pop().unwrap();
    println!("Bootstrap node: {}", bootstrap_node.local_enr().node_id());
    println!("Target node: {}", target_node.local_enr().node_id());
    for swarm in swarms.iter_mut() {
        let key: kbucket::Key<NodeId> = swarm.local_enr().node_id().into();
        let distance = key
            .log2_distance(&bootstrap_node.local_enr().node_id().into())
            .unwrap();
        println!(
            "Distance of node {} relative to node {}: {}",
            swarm.local_enr().node_id(),
            bootstrap_node.local_enr().node_id(),
            distance
        );
        swarm.add_enr(bootstrap_node.local_enr().clone()).unwrap();
        bootstrap_node.add_enr(swarm.local_enr().clone()).unwrap();
    }
    // Start a FINDNODE query of target
    let target_random_node_id = target_node.local_enr().node_id();
    swarms.first_mut().unwrap().find_node(target_random_node_id);
    swarms.push(bootstrap_node);
    Runtime::new()
        .unwrap()
        .block_on(future::poll_fn(move || -> Result<_, io::Error> {
            for swarm in swarms.iter_mut() {
                loop {
                    match swarm.poll().unwrap() {
                        Async::Ready(Some(Discv5Event::FindNodeResult {
                            closer_peers, ..
                        })) => {
                            println!(
                                "Query found {} peers, Total peers {}",
                                closer_peers.len(),
                                total_nodes
                            );
                            assert!(closer_peers.len() == total_nodes);
                            return Ok(Async::Ready(()));
                        }
                        Async::Ready(_) => (),
                        Async::NotReady => break,
                    }
                }
            }
            Ok(Async::NotReady)
        }))
        .unwrap();
}

#[test]
fn test_findnode_query() {
    init();
    // build a collection of 8 nodes
    let total_nodes = 8;
    let mut swarms = build_swarms(total_nodes, 30000);
    let node_enrs: Vec<Enr<CombinedKey>> = swarms.iter().map(|n| n.local_enr().clone()).collect();

    // link the nodes together
    for (swarm, previous_node_enr) in swarms.iter_mut().skip(1).zip(node_enrs.clone()) {
        let key: kbucket::Key<NodeId> = swarm.local_enr().node_id().clone().into();
        let distance = key
            .log2_distance(&previous_node_enr.node_id().clone().into())
            .unwrap();
        println!("Distance of node relative to next: {}", distance);
        swarm.add_enr(previous_node_enr).unwrap();
    }

    // pick a random node target
    let target_random_node_id = NodeId::random();

    // start a query on the last node
    swarms
        .last_mut()
        .unwrap()
        .find_node(target_random_node_id.clone());

    // build expectations
    let expected_node_ids: Vec<NodeId> = node_enrs
        .iter()
        .map(|enr| enr.node_id().clone())
        .take(total_nodes - 1)
        .collect();

    let test_result = Arc::new(Mutex::new(true));
    let thread_result = test_result.clone();

    tokio::run(
        future::poll_fn(move || -> Result<_, io::Error> {
            for swarm in swarms.iter_mut() {
                loop {
                    match swarm.poll().unwrap() {
                        Async::Ready(Some(Discv5Event::FindNodeResult { key, closer_peers })) => {
                            // NOTE: The number of peers found is statistical, as we only ask
                            // peers for specific buckets, there is a chance our node doesn't
                            // exist if the first few buckets asked for.
                            assert_eq!(key, target_random_node_id);
                            println!(
                                "Query found {} peers. Total peers were: {}",
                                closer_peers.len(),
                                expected_node_ids.len()
                            );
                            assert!(closer_peers.len() <= expected_node_ids.len());
                            return Ok(Async::Ready(()));
                        }
                        Async::Ready(_) => (),
                        Async::NotReady => break,
                    }
                }
            }
            Ok(Async::NotReady)
        })
        .timeout(Duration::from_millis(500))
        .map_err(move |_| *thread_result.lock().unwrap() = false)
        .map(|_| ()),
    );

    assert!(*test_result.lock().unwrap());
}

#[test]
fn test_updating_connection_on_ping() {
    let key = identity::Keypair::generate_secp256k1();
    let enr_key1: CombinedKey = key.clone().try_into().unwrap();
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
    let mut discv5: Discv5<Box<u64>> = Discv5::new(enr, key.clone(), config, socket_addr).unwrap();
    discv5.add_enr(enr2.clone()).unwrap();
    discv5.connection_updated(enr2.node_id().clone(), None, NodeStatus::Disconnected);

    let mut buckets = discv5.kbuckets.clone();
    let mut node = buckets.iter().next().unwrap();
    assert_eq!(node.status, NodeStatus::Disconnected);

    // Add a fake request
    let ping_response = rpc::Response::Ping {
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
#[test]
fn test_table_limits() {
    // this seed generates 12 node id's that are distributed accross buckets such that no more than
    // 2 exist in a single bucket.
    let keypairs = generate_deterministic_keypair(12, 9487);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let enr_key: CombinedKey = keypairs[0].clone().try_into().unwrap();
    let config = Discv5ConfigBuilder::new().ip_limit(true).build();
    let enr = EnrBuilder::new("v4")
        .ip(ip.clone().into())
        .udp(9050)
        .build(&enr_key)
        .unwrap();

    let socket_addr = enr.udp_socket().unwrap();
    let mut discv5: Discv5<Box<u64>> =
        Discv5::new(enr, keypairs[0].clone(), config, socket_addr).unwrap();
    let table_limit: usize = 10;
    // Generate `table_limit + 2` nodes in the same subnet.
    let enrs: Vec<Enr<CombinedKey>> = (1..=table_limit + 1)
        .map(|i| {
            let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
            let enr_key: CombinedKey = keypairs[i].clone().try_into().unwrap();
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
#[test]
fn test_bucket_limits() {
    let key = identity::Keypair::generate_secp256k1();
    let enr_key: CombinedKey = key.clone().try_into().unwrap();
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
    let mut discv5: Discv5<Box<u64>> = Discv5::new(enr, key.clone(), config, socket_addr).unwrap();
    for enr in enrs {
        discv5.add_enr(enr.clone()).unwrap();
    }

    // Number of entries should be equal to `bucket_limit`.
    assert_eq!(
        discv5.kbuckets_entries().collect::<Vec<_>>().len(),
        bucket_limit
    );
}

fn update_enr(swarm: &mut SwarmType, key: &str, value: &[u8]) -> bool {
    if let Ok(_) = swarm.enr_insert(key, value.to_vec()) {
        return true;
    } else {
        return false;
    }
}

#[test]
fn test_predicate_search() {
    init();
    let total_nodes = 10;
    // Seed is chosen such that all nodes are in the 256th bucket of bootstrap
    let seed = 1652;
    // Generate `num_nodes` + bootstrap_node and target_node keypairs from given seed
    let keypairs = generate_deterministic_keypair(total_nodes + 2, seed);
    let mut swarms = build_swarms_from_keypairs(keypairs, 12000);
    // Last node is bootstrap node in a star topology
    let mut bootstrap_node = swarms.remove(0);
    // target_node is not polled.
    let target_node = swarms.pop().unwrap();

    // Update `num_nodes` with the required attnet value
    let num_nodes = total_nodes / 2;
    let required_attnet_value = vec![1, 0, 0, 0];
    let unwanted_attnet_value = vec![0, 0, 0, 0];
    println!("Bootstrap node: {}", bootstrap_node.local_enr().node_id());
    println!("Target node: {}", target_node.local_enr().node_id());

    for (i, swarm) in swarms.iter_mut().enumerate() {
        let key: kbucket::Key<NodeId> = swarm.local_enr().node_id().into();
        let distance = key
            .log2_distance(&bootstrap_node.local_enr().node_id().into())
            .unwrap();
        println!(
            "Distance of node {} relative to node {}: {}",
            swarm.local_enr().node_id(),
            bootstrap_node.local_enr().node_id(),
            distance
        );
        swarm.add_enr(bootstrap_node.local_enr().clone()).unwrap();
        if i % 2 == 0 {
            update_enr(swarm, "attnets", &unwanted_attnet_value);
        } else {
            update_enr(swarm, "attnets", &required_attnet_value);
        }
        bootstrap_node.add_enr(swarm.local_enr().clone()).unwrap();
    }

    // Predicate function for filtering enrs
    let predicate = move |enr: &Enr<CombinedKey>| {
        if let Some(v) = enr.get("attnets") {
            return *v == required_attnet_value;
        } else {
            return false;
        }
    };

    // Start a find enr predicate query
    let target_random_node_id = target_node.local_enr().node_id();
    swarms
        .first_mut()
        .unwrap()
        .find_enr_predicate(target_random_node_id, predicate, total_nodes);
    swarms.push(bootstrap_node);
    Runtime::new()
        .unwrap()
        .block_on(future::poll_fn(move || -> Result<_, io::Error> {
            for swarm in swarms.iter_mut() {
                loop {
                    match swarm.poll().unwrap() {
                        Async::Ready(Some(Discv5Event::FindNodeResult {
                            closer_peers, ..
                        })) => {
                            println!(
                                "Query found {} peers, Total peers {}",
                                closer_peers.len(),
                                total_nodes
                            );
                            println!("Nodes expected to pass predicate search {}", num_nodes);
                            assert!(closer_peers.len() == num_nodes);
                            return Ok(Async::Ready(()));
                        }
                        Async::Ready(_) => (),
                        Async::NotReady => break,
                    }
                }
            }
            Ok(Async::NotReady)
        }))
        .unwrap();
}
