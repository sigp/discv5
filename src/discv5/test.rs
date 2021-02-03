#![cfg(test)]

use crate::{kbucket, Discv5, *};
use enr::{CombinedKey, Enr, EnrBuilder, EnrKey, NodeId};
use rand_core::{RngCore, SeedableRng};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

fn init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

fn update_enr(discv5: &mut Discv5, key: &str, value: &[u8]) -> bool {
    discv5.enr_insert(key, value).is_ok()
}

async fn build_nodes(n: usize, base_port: u16) -> Vec<Discv5> {
    let mut nodes = Vec::new();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    for port in base_port..base_port + n as u16 {
        let enr_key = CombinedKey::generate_secp256k1();
        let config = Discv5Config::default();

        let enr = EnrBuilder::new("v4")
            .ip(ip)
            .udp(port)
            .build(&enr_key)
            .unwrap();
        // transport for building a swarm
        let socket_addr = enr.udp_socket().unwrap();
        let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();
        discv5.start(socket_addr).await.unwrap();
        nodes.push(discv5);
    }
    nodes
}

/// Build `n` swarms using passed keypairs.
async fn build_nodes_from_keypairs(keys: Vec<CombinedKey>, base_port: u16) -> Vec<Discv5> {
    let mut nodes = Vec::new();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    for (i, enr_key) in keys.into_iter().enumerate() {
        let port = base_port + i as u16;

        let config = Discv5ConfigBuilder::new().build();
        let enr = EnrBuilder::new("v4")
            .ip(ip)
            .udp(port)
            .build(&enr_key)
            .unwrap();

        let socket_addr = enr.udp_socket().unwrap();
        let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();
        discv5.start(socket_addr).await.unwrap();
        nodes.push(discv5);
    }
    nodes
}

/// Generate `n` deterministic keypairs from a given seed.
fn generate_deterministic_keypair(n: usize, seed: u64) -> Vec<CombinedKey> {
    let mut keypairs = Vec::new();
    for i in 0..n {
        let sk = {
            let rng = &mut rand_xorshift::XorShiftRng::seed_from_u64(seed + i as u64);
            let mut b = [0; 32];
            loop {
                // until a value is given within the curve order
                rng.fill_bytes(&mut b);
                if let Ok(k) = k256::ecdsa::SigningKey::from_bytes(&b) {
                    break k;
                }
            }
        };
        let kp = CombinedKey::from(sk);
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

/// This is a smaller version of the star topology test designed to debug issues with queries.
#[tokio::test]
async fn test_discovery_three_peers() {
    init();
    let total_nodes = 3;
    // Seed is chosen such that all nodes are in the 256th bucket of bootstrap
    let seed = 1652;
    // Generate `num_nodes` + bootstrap_node and target_node keypairs from given seed
    let keypairs = generate_deterministic_keypair(total_nodes + 2, seed);
    let mut nodes = build_nodes_from_keypairs(keypairs, 11200).await;
    // Last node is bootstrap node in a star topology
    let mut bootstrap_node = nodes.remove(0);
    // target_node is not polled.
    let target_node = nodes.pop().unwrap();
    println!("Bootstrap node: {}", bootstrap_node.local_enr().node_id());
    println!("Target node: {}", target_node.local_enr().node_id());
    let key: kbucket::Key<NodeId> = target_node.local_enr().node_id().into();
    let distance = key
        .log2_distance(&bootstrap_node.local_enr().node_id().into())
        .unwrap();
    println!(
        "Distance of target_node {} relative to bootstrap {}: {}",
        target_node.local_enr().node_id(),
        bootstrap_node.local_enr().node_id(),
        distance
    );
    for node in nodes.iter_mut() {
        let key: kbucket::Key<NodeId> = node.local_enr().node_id().into();
        let distance = key
            .log2_distance(&bootstrap_node.local_enr().node_id().into())
            .unwrap();
        println!(
            "Distance of node {} relative to bootstrap {}: {}",
            node.local_enr().node_id(),
            bootstrap_node.local_enr().node_id(),
            distance
        );
        node.add_enr(bootstrap_node.local_enr().clone()).unwrap();
        bootstrap_node.add_enr(node.local_enr().clone()).unwrap();
    }

    // Start a FINDNODE query of target
    let target_random_node_id = target_node.local_enr().node_id();
    nodes.push(bootstrap_node);
    let result_nodes = nodes
        .first_mut()
        .unwrap()
        .find_node(target_random_node_id)
        .await
        .unwrap();
    println!(
        "Query found {} peers, Total peers {}",
        result_nodes.len(),
        total_nodes
    );
    assert!(result_nodes.len() == total_nodes);
}

/// Test for a star topology with `num_nodes` connected to a `bootstrap_node`
/// FINDNODE request is sent from any of the `num_nodes` nodes to a `target_node`
/// which isn't part of the swarm.
/// The seed for the keypair generation is chosen such that all `num_nodes` nodes
/// and the `target_node` are in the 256th k-bucket of the bootstrap node.
/// This ensures that all nodes are found in a single FINDNODE query.
#[tokio::test]
async fn test_discovery_star_topology() {
    init();
    let total_nodes = 10;
    // Seed is chosen such that all nodes are in the 256th bucket of bootstrap
    let seed = 1652;
    // Generate `num_nodes` + bootstrap_node and target_node keypairs from given seed
    let keypairs = generate_deterministic_keypair(total_nodes + 2, seed);
    let mut nodes = build_nodes_from_keypairs(keypairs, 11000).await;
    // Last node is bootstrap node in a star topology
    let mut bootstrap_node = nodes.remove(0);
    // target_node is not polled.
    let target_node = nodes.pop().unwrap();
    println!("Bootstrap node: {}", bootstrap_node.local_enr().node_id());
    let key: kbucket::Key<NodeId> = target_node.local_enr().node_id().into();
    let distance = key
        .log2_distance(&bootstrap_node.local_enr().node_id().into())
        .unwrap();
    println!("Target node: {}", target_node.local_enr().node_id());
    println!(
        "Distance of target_node {} relative to bootstrap {}: {}",
        target_node.local_enr().node_id(),
        bootstrap_node.local_enr().node_id(),
        distance
    );
    for node in nodes.iter_mut() {
        let key: kbucket::Key<NodeId> = node.local_enr().node_id().into();
        let distance = key
            .log2_distance(&bootstrap_node.local_enr().node_id().into())
            .unwrap();
        println!(
            "Distance of node {} relative to bootstrap node {}: {}",
            node.local_enr().node_id(),
            bootstrap_node.local_enr().node_id(),
            distance
        );
        node.add_enr(bootstrap_node.local_enr().clone()).unwrap();
        bootstrap_node.add_enr(node.local_enr().clone()).unwrap();
    }
    // Start a FINDNODE query of target
    let target_random_node_id = target_node.local_enr().node_id();
    nodes.push(bootstrap_node);
    let result_nodes = nodes
        .first_mut()
        .unwrap()
        .find_node(target_random_node_id)
        .await
        .unwrap();
    println!(
        "Query found {} peers, Total peers {}",
        result_nodes.len(),
        total_nodes
    );
    assert!(result_nodes.len() == total_nodes);
}

#[tokio::test]
async fn test_findnode_query() {
    init();
    // build a collection of 8 nodes
    let total_nodes = 8;
    let mut nodes = build_nodes(total_nodes, 30000).await;
    let node_enrs: Vec<Enr<CombinedKey>> = nodes.iter().map(|n| n.local_enr()).collect();

    // link the nodes together
    for (node, previous_node_enr) in nodes.iter_mut().skip(1).zip(node_enrs.clone()) {
        let key: kbucket::Key<NodeId> = node.local_enr().node_id().clone().into();
        let distance = key
            .log2_distance(&previous_node_enr.node_id().clone().into())
            .unwrap();
        println!("Distance of node relative to next: {}", distance);
        node.add_enr(previous_node_enr).unwrap();
    }

    // pick a random node target
    let target_random_node_id = NodeId::random();

    // start a query on the last node
    let found_nodes = nodes
        .last_mut()
        .unwrap()
        .find_node(target_random_node_id)
        .await
        .unwrap();

    // build expectations
    let expected_node_ids: Vec<NodeId> = node_enrs
        .iter()
        .map(|enr| enr.node_id())
        .take(total_nodes - 1)
        .collect();

    // NOTE: The number of peers found is statistical, as we only ask
    // peers for specific buckets, there is a chance our node doesn't
    // exist if the first few buckets asked for.
    println!(
        "Query with found {} peers. Total peers were: {}",
        found_nodes.len(),
        expected_node_ids.len()
    );
    assert!(found_nodes.len() <= expected_node_ids.len());
}

#[tokio::test]
async fn test_predicate_search() {
    init();
    let total_nodes = 10;
    // Seed is chosen such that all nodes are in the 256th bucket of bootstrap
    let seed = 1652;
    // Generate `num_nodes` + bootstrap_node and target_node keypairs from given seed
    let keypairs = generate_deterministic_keypair(total_nodes + 2, seed);
    let mut nodes = build_nodes_from_keypairs(keypairs, 12000).await;
    // Last node is bootstrap node in a star topology
    let mut bootstrap_node = nodes.remove(0);
    // target_node is not polled.
    let target_node = nodes.pop().unwrap();

    // Update `num_nodes` with the required attnet value
    let num_nodes = total_nodes / 2;
    let required_attnet_value = vec![1, 0, 0, 0];
    let unwanted_attnet_value = vec![0, 0, 0, 0];
    println!("Bootstrap node: {}", bootstrap_node.local_enr().node_id());
    println!("Target node: {}", target_node.local_enr().node_id());

    for (i, swarm) in nodes.iter_mut().enumerate() {
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
            v == required_attnet_value.as_slice()
        } else {
            false
        }
    };
    nodes.push(bootstrap_node);

    // Start a find enr predicate query
    let target_random_node_id = target_node.local_enr().node_id();
    let found_nodes = nodes
        .first_mut()
        .unwrap()
        .find_node_predicate(target_random_node_id, Box::new(predicate), total_nodes)
        .await
        .unwrap();

    println!(
        "Query found {} peers. Total peers were: {}",
        found_nodes.len(),
        total_nodes,
    );
    println!("Nodes expected to pass predicate search {}", num_nodes);
    assert!(found_nodes.len() == num_nodes);
}

// The kbuckets table can have maximum 10 nodes in the same /24 subnet across all buckets
#[tokio::test]
async fn test_table_limits() {
    // this seed generates 12 node id's that are distributed accross buckets such that no more than
    // 2 exist in a single bucket.
    let mut keypairs = generate_deterministic_keypair(12, 9487);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let enr_key: CombinedKey = keypairs.remove(0);
    let config = Discv5ConfigBuilder::new().ip_limit().build();
    let enr = EnrBuilder::new("v4")
        .ip(ip)
        .udp(9050)
        .build(&enr_key)
        .unwrap();

    // let socket_addr = enr.udp_socket().unwrap();
    let mut discv5: Discv5 = Discv5::new(enr, enr_key, config).unwrap();
    let table_limit: usize = 10;
    // Generate `table_limit + 2` nodes in the same subnet.
    let enrs: Vec<Enr<CombinedKey>> = (1..=table_limit + 1)
        .map(|i| {
            let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
            let enr_key: CombinedKey = keypairs.remove(0);
            EnrBuilder::new("v4")
                .ip(ip)
                .udp(9050 + i as u16)
                .build(&enr_key)
                .unwrap()
        })
        .collect();
    for enr in enrs {
        discv5.add_enr(enr.clone()).unwrap();
    }
    // Number of entries should be `table_limit`, i.e one node got restricted
    assert_eq!(discv5.kbuckets.read().iter_ref().count(), table_limit);
}

// Each bucket can have maximum 2 nodes in the same /24 subnet
#[tokio::test]
async fn test_bucket_limits() {
    let enr_key = CombinedKey::generate_secp256k1();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let enr = EnrBuilder::new("v4")
        .ip(ip)
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
                .ip(ip)
                .udp(9500 + i as u16)
                .build(kp)
                .unwrap()
        })
        .collect();

    let config = Discv5ConfigBuilder::new().ip_limit().build();
    let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();
    for enr in enrs {
        discv5.add_enr(enr.clone()).unwrap();
    }

    // Number of entries should be equal to `bucket_limit`.
    assert_eq!(discv5.kbuckets.read().iter_ref().count(), bucket_limit);
}
