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

use clap::Parser;
use discv5::{
    enr,
    enr::{k256, CombinedKey},
    Discv5, Discv5ConfigBuilder,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tracing::{info, warn};

#[derive(Parser)]
struct FindNodesArgs {
    /// Ip to bind. To get local Ipv6 - Ipv4 communication use UNSPECIFIED addresses instead of
    /// LOCALHOST (:: instead of ::1, 0.0.0.0 instead of 127.0.0.1)
    ip: IpAddr,
    /// Port to bind
    port: u16,
    /// Generate a new key instead of the default testing one.
    #[clap(long)]
    generate_key: bool,
    /// Set the ip and port in the ENR for advertisement to other peers.
    #[clap(long)]
    set_enr_socket: bool,
    /// A remote peer to try to connect to.
    peer: Option<discv5::Enr>,
}

impl Default for FindNodesArgs {
    fn default() -> Self {
        FindNodesArgs {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            set_enr_socket: false,
            port: 9000,
            generate_key: false,
            peer: None,
        }
    }
}

#[tokio::main]
async fn main() {
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("trace"))
        .unwrap();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter_layer)
        .try_init();

    let args = FindNodesArgs::parse();

    let enr_key = if args.generate_key {
        // use a new key if specified
        CombinedKey::generate_secp256k1()
    } else {
        // A fixed key for testing
        let raw_key =
            hex::decode("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
                .unwrap();
        let secret_key = k256::ecdsa::SigningKey::from_bytes(&raw_key).unwrap();
        CombinedKey::from(secret_key)
    };

    let enr = {
        let mut builder = enr::EnrBuilder::new("v4");
        if args.set_enr_socket {
            match args.ip {
                IpAddr::V4(ip4) => {
                    builder.ip4(ip4).udp4(args.port);
                }
                IpAddr::V6(ip6) => {
                    builder.ip6(ip6).udp6(args.port);
                }
            }
        }
        builder.build(&enr_key).unwrap()
    };

    // default configuration with packet filtering
    // let config = Discv5ConfigBuilder::new().enable_packet_filter().build();
    // default configuration without packet filtering
    let config = {
        let mut builder = &mut Discv5ConfigBuilder::new();
        if args.ip.is_ipv6() {
            println!("Setting dual stack ipv6 mode with mapped addresses enabled");
            builder = builder.ip_mode(discv5::IpMode::Ip6 {
                enable_mapped_addresses: true,
            });
        }
        builder.build()
    };

    info!("Node Id: {}", enr.node_id());
    if args.set_enr_socket {
        // if the ENR is useful print it
        info!("Base64 ENR: {}", enr.to_base64());
        if args.ip.is_ipv6() {
            info!("IpV6 socket: {}", enr.udp6_socket().unwrap());
        } else {
            info!("IpV4 socket: {}", enr.udp4_socket().unwrap());
        }
    }

    // the address to listen on.
    let socket_addr = SocketAddr::new(args.ip, args.port);

    // construct the discv5 server
    let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();

    // if we know of another peer's ENR, add it known peers
    if let Some(enr) = args.peer {
        info!(
            "Remote ENR read. ip4: {:?}, ip6:{:?}, udp_port {:?}, tcp_port: {:?}",
            enr.ip4(),
            enr.ip6(),
            enr.udp4(),
            enr.tcp4()
        );
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
                info!("Connected peers: {}, Active sessions: {}, Unsolicited requests/s: {:.2}", connected_peers, metrics.active_sessions, metrics.unsolicited_requests_per_second);
                info!("Searching for peers...");
                // execute a FINDNODE query
                match discv5.find_node(target_random_node_id).await {
                    Err(e) => warn!("Find Node result failed: {:?}", e),
                    Ok(v) => {
                        // found a list of ENR's print their NodeIds
                        let node_ids = v.iter().map(|enr| enr.node_id()).collect::<Vec<_>>();
                        info!("Nodes found: {}", node_ids.len());
                        for node_id in node_ids {
                            info!("Node: {}", node_id);
                        }
                    }
                }
            }
        }
    }
}
