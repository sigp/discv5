//! Demonstrates how to run a basic Discovery v5 Service.
//!
//! This example creates a discv5 service which searches for peers every 30 seconds. On
//! creation, the local ENR created for this service is displayed in base64. This can be used to
//! allow other instances to connect and join the network. The service can be stopped by pressing
//! Ctrl-C.
//!
//! To add peers to the network, create multiple instances of this service adding the ENR of a
//! participating node in the command line. The nodes should discover each other over a period of
//! time. (It is probabilistic that nodes to find each other on any given query).
//!
//! A single instance listening on a UDP socket `127.0.0.1:9000` (with an ENR that has an empty IP
//! and UDP port) can be created via:
//!
//! ```
//! sh cargo run --example find_nodes
//! ```
//!
//! As the associated ENR has no IP/Port it is not displayed, as it cannot be used to connect to.
//!
//! An ENR IP address (to allow another nodes to dial this service), port and ENR node can also be
//! passed as command line options. Therefore, a second instance, in a new terminal, can be run on
//! port 9001 and connected to another node with a valid ENR:
//!
//! ```
//! sh cargo run --example find_nodes -- 127.0.0.1 9001 <GENERATE_KEY> <BASE64_ENR>
//! ```
//!
//! where `<BASE64_ENR>` is the base64 ENR given from executing the first node with an IP and port
//! given in the CLI.
//! `<GENERATE_KEY>` is a boolean (`true` or `false`) specifying if a new key should be generated.
//! These steps can be repeated to add further nodes to the test network.
//!
//! The parameters are optional.
//!
//!  For a simple CLI discovery service see [discv5-cli](https://github.com/AgeManning/discv5-cli)

use discv5::{enr, enr::CombinedKey, Discv5, Discv5Config, Discv5Event};
use futures::prelude::*;
use std::{
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::stream::Stream;

#[tokio::main]
async fn main() {
    env_logger::init();

    // if there is an address specified use it
    let address = {
        if let Some(address) = std::env::args().nth(1) {
            address.parse::<Ipv4Addr>().unwrap()
        } else {
            "127.0.0.1".parse::<Ipv4Addr>().unwrap()
        }
    };

    let port = {
        if let Some(udp_port) = std::env::args().nth(2) {
            u16::from_str_radix(&udp_port, 10).unwrap()
        } else {
            9000
        }
    };

    // A fixed key for testing
    let raw_key = vec![
        183, 28, 113, 166, 126, 17, 119, 173, 78, 144, 22, 149, 225, 180, 185, 238, 23, 174, 22,
        198, 102, 141, 49, 62, 172, 47, 150, 219, 205, 163, 242, 145,
    ];
    let secret_key = secp256k1::SecretKey::parse_slice(&raw_key).unwrap();
    let mut enr_key = CombinedKey::from(secret_key);

    // use a random key if specified
    if let Some(generate_key) = std::env::args().nth(3) {
        if generate_key.parse::<bool>().unwrap() {
            enr_key = CombinedKey::generate_secp256k1();
        }
    }

    // construct a local ENR
    let enr = {
        let mut builder = enr::EnrBuilder::new("v4");
        // if an IP was specified, use it
        if std::env::args().nth(1).is_some() {
            builder.ip(address.into());
        }
        // if a port was specified, use it
        if std::env::args().nth(2).is_some() {
            builder.udp(port);
        }
        builder.build(&enr_key).unwrap()
    };

    // if the ENR is useful print it
    println!("Node Id: {}", enr.node_id());
    if enr.udp_socket().is_some() {
        println!("Base64 ENR: {}", enr.to_base64());
        println!("IP: {}, UDP_PORT:{}", enr.ip().unwrap(), enr.udp().unwrap());
    } else {
        println!("ENR is not printed as no IP:PORT was specified");
    }

    // default configuration
    let config = Discv5Config::default();

    // the address to listen on
    let socket_addr = SocketAddr::new(address.into(), port);

    // construct the discv5 service, initializing an unused transport layer
    let mut discv5 = Discv5::new(enr, enr_key, config, socket_addr).unwrap();

    // if we know of another peer's ENR, add it known peers
    if let Some(base64_enr) = std::env::args().nth(4) {
        match base64_enr.parse::<enr::Enr<enr::CombinedKey>>() {
            Ok(enr) => {
                println!(
                    "ENR Read. ip: {:?}, udp_port {:?}, tcp_port: {:?}",
                    enr.ip(),
                    enr.udp(),
                    enr.tcp()
                );
                if let Err(e) = discv5.add_enr(enr) {
                    println!("ENR was not added: {}", e);
                }
            }
            Err(e) => panic!("Decoding ENR failed: {}", e),
        }
    }
    // construct a 30 second interval to search for new peers.
    let mut query_interval = tokio::time::interval(Duration::from_secs(30));

    // Kick it off!
    future::poll_fn(move |cx: &mut Context| -> std::task::Poll<()> {
        loop {
            // start a query if it's time to do so
            if let Poll::Ready(Some(_)) = Pin::new(&mut query_interval).poll_next(cx) {
                // pick a random node target
                let target_random_node_id = enr::NodeId::random();
                println!("Connected Peers: {}", discv5.connected_peers());
                println!("Searching for peers...");
                // execute a FINDNODE query
                discv5.find_node(target_random_node_id);
            }

            match discv5.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => match event {
                    Discv5Event::FindNodeResult {
                        closer_peers,
                        query_id,
                        ..
                    } => {
                        if !closer_peers.is_empty() {
                            println!("Query with id {} Completed. Nodes found:", query_id.0);
                            for n in closer_peers {
                                println!("Node: {}", n);
                            }
                        } else {
                            println!("Query Completed. No peers found.")
                        }
                    }
                    _ => (),
                },
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await;
}
