//! Demonstrates how to run a basic Discovery v5 Service.
//!
//! This example creates a discv5 service which searches for peers every 60 seconds. On
//! creation, the local ENR created for this service is displayed in base64. This can be used to
//! allow other instances to connect and join the network. The service can be stopped by pressing
//! Ctrl-C.
//!
//! To add peers to the network, create multiple instances of this service adding the ENR of a
//! participating node in the command line. The nodes should discover each other over a period of
//! time. (It is probabilistic that nodes to find each other on any given query).
//!
//! A single instance listening on a UDP socket `0.0.0.0:9000` (with an ENR that has an empty IP
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
//! Here `127.0.0.1` represents the external IP address that others may connect to this node on. The
//! `9001` represents the external port and the port to listen on. The `<BASE64_ENR>` is the base64
//! ENR given from executing the first node with an IP and port
//! given in the CLI.
//! `<GENERATE_KEY>` is a boolean (`true` or `false`) specifying if a new key should be generated.
//! These steps can be repeated to add further nodes to the test network.
//!
//! The parameters are optional.
//!
//!  For a simple CLI discovery service see [discv5-cli](https://github.com/AgeManning/discv5-cli)

use discv5::{
    enr,
    enr::{k256, CombinedKey},
    Discv5, Discv5ConfigBuilder,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

#[tokio::main]
async fn main() {
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter_layer)
        .try_init();

    // if there is an address specified use it
    let address = std::env::args()
        .nth(1)
        .map(|addr| addr.parse::<Ipv4Addr>().unwrap());

    let port = {
        if let Some(udp_port) = std::env::args().nth(2) {
            udp_port.parse().unwrap()
        } else {
            9000
        }
    };

    // A fixed key for testing
    let raw_key =
        hex::decode("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291").unwrap();
    let secret_key = k256::ecdsa::SigningKey::from_bytes(&raw_key).unwrap();
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
        if let Some(external_address) = address {
            builder.ip(external_address.into());
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

    // default configuration with packet filtering
    // let config = Discv5ConfigBuilder::new().enable_packet_filter().build();
    // default configuration without packet filtering
    let config = Discv5ConfigBuilder::new().build();

    // the address to listen on
    let socket_addr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), port);

    // construct the discv5 server
    let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();

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

    // start the discv5 service
    discv5.start(socket_addr).await.unwrap();

    // construct a 30 second interval to search for new peers.
    let mut query_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = query_interval.tick() => {
                // pick a random node target
                let target_random_node_id = enr::NodeId::random();
                // get metrics
                let metrics = discv5.metrics();
                let connected_peers = discv5.connected_peers();
                println!("Connected peers: {}, Active sessions: {}, Unsolicited requests/s: {:.2}", connected_peers, metrics.active_sessions, metrics.unsolicited_requests_per_second);
                println!("Searching for peers...");
                // execute a FINDNODE query
                match discv5.find_node(target_random_node_id).await {
                    Err(e) => println!("Find Node result failed: {:?}", e),
                    Ok(v) => {
                        // found a list of ENR's print their NodeIds
                        let node_ids = v.iter().map(|enr| enr.node_id()).collect::<Vec<_>>();
                        println!("Nodes found: {}", node_ids.len());
                        for node_id in node_ids {
                            println!("Node: {}", node_id);
                        }
                    }
                }
            }
        }
    }
}
