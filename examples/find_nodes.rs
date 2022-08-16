//! Demonstrates how to run a basic Discovery v5 Service.
//!
//! This example creates a discv5 service which searches for peers every 30 seconds. On creation,
//! the local ENR created for this service is displayed in base64. This can be used to allow other
//! instances to connect and join the network. The service can be stopped by pressing Ctrl-C.
//!
//! To add peers to the network, create multiple instances of this service adding the ENR of a
//! participating node in the command line. The nodes should discover each other over a period of
//! time. (It is probabilistic that nodes to find each other on any given query).
//!
//! See the example's help with
//! ```
//! sh cargo run --example find_nodes -- --help
//! ```
//!
//! For a simple CLI discovery service see [discv5-cli](https://github.com/AgeManning/discv5-cli)

use clap::Parser;
use discv5::{
    enr,
    enr::{k256, CombinedKey},
    Discv5, Discv5ConfigBuilder, Discv5Event,
};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tracing::{info, warn};

#[derive(Parser)]
struct FindNodesArgs {
    /// Type of socket to bind ['ds', 'ip4', 'ip6']. The dual stack option will enable mapped
    /// addresses over an IpV6 socket.
    #[clap(long, default_value_t = SocketKind::Ds)]
    socket_kind: SocketKind,
    /// IpV4 to advertise in the ENR. This is needed so that other IpV4 nodes can connect to us.
    #[clap(long)]
    enr_ip4: Option<Ipv4Addr>,
    /// IpV6 to advertise in the ENR. This is needed so that other IpV6 nodes can connect to us.
    #[clap(long)]
    enr_ip6: Option<Ipv6Addr>,
    /// Port to bind. If none is provided, a random one in the 9000 - 9999 range will be picked
    /// randomly.
    #[clap(long)]
    port: Option<u16>,
    /// Use a default test key.
    #[clap(long)]
    use_test_key: bool,
    /// A remote peer to try to connect to. Several peers can be added repeating this option.
    #[clap(long)]
    remote_peer: Vec<discv5::Enr>,
    /// Use this option to turn on printing events received from discovery.
    #[clap(long)]
    events: bool,
}

#[tokio::main]
async fn main() {
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter_layer)
        .try_init();

    let args = FindNodesArgs::parse();
    let port = args
        .port
        .unwrap_or_else(|| (rand::random::<u16>() % 1000) + 9000);

    let enr_key = if args.use_test_key {
        // A fixed key for testing
        let raw_key =
            hex::decode("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
                .unwrap();
        let secret_key = k256::ecdsa::SigningKey::from_bytes(&raw_key).unwrap();
        CombinedKey::from(secret_key)
    } else {
        // use a new key if specified
        CombinedKey::generate_secp256k1()
    };

    let enr = {
        let mut builder = enr::EnrBuilder::new("v4");
        if let Some(ip4) = args.enr_ip4 {
            // if the given address is the UNSPECIFIED address we want to advertise localhost
            if ip4.is_unspecified() {
                builder.ip4(Ipv4Addr::LOCALHOST).udp4(port);
            } else {
                builder.ip4(ip4).udp4(port);
            }
        }
        if let Some(ip6) = args.enr_ip6 {
            // if the given address is the UNSPECIFIED address we want to advertise localhost
            if ip6.is_unspecified() {
                builder.ip6(Ipv6Addr::LOCALHOST).udp6(port);
            } else {
                builder.ip6(ip6).udp6(port);
            }
        }
        builder.build(&enr_key).unwrap()
    };

    // default configuration with packet filtering
    // let config = Discv5ConfigBuilder::new().enable_packet_filter().build();

    // default configuration without packet filtering
    let config = Discv5ConfigBuilder::new()
        .ip_mode(match args.socket_kind {
            SocketKind::Ip4 => discv5::IpMode::Ip4,
            SocketKind::Ip6 => discv5::IpMode::Ip6 {
                enable_mapped_addresses: false,
            },
            SocketKind::Ds => discv5::IpMode::Ip6 {
                enable_mapped_addresses: true,
            },
        })
        .build();

    info!("Node Id: {}", enr.node_id());
    if args.enr_ip6.is_some() || args.enr_ip4.is_some() {
        // if the ENR is useful print it
        info!("Base64 ENR: {}", enr.to_base64());
        info!(
            "Local ENR IpV6 socket: {:?}. Local ENR IpV4 socket: {:?}",
            enr.udp6_socket(),
            enr.udp4_socket()
        );
    }
    // the address to listen on.
    let bind_addr = match args.socket_kind {
        SocketKind::Ip4 => Ipv4Addr::UNSPECIFIED.into(),
        SocketKind::Ip6 | SocketKind::Ds => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket_addr = SocketAddr::new(bind_addr, port);

    // construct the discv5 server
    let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();

    // if we know of another peer's ENR, add it known peers
    for enr in args.remote_peer {
        info!(
            "Remote ENR read. udp4 socket: {:?}, udp6 socket: {:?}, tcp4_port {:?}, tcp6_port: {:?}",
            enr.udp4_socket(),
            enr.udp6_socket(),
            enr.tcp4(),
            enr.tcp6()
        );
        if let Err(e) = discv5.add_enr(enr) {
            warn!("Failed to add remote ENR {}", e);
            // It's unlikely we want to continue in this example after this
            return;
        };
    }

    // start the discv5 service
    discv5.start(socket_addr).await.unwrap();
    let mut event_stream = discv5.event_stream().await.unwrap();
    let check_evs = args.events;

    // construct a 30 second interval to search for new peers.
    let mut query_interval = tokio::time::interval(Duration::from_secs(30));

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
            Some(discv5_ev) = event_stream.recv() => {
                // consume the events even if not printed
                if !check_evs {
                    continue;
                }
                match discv5_ev {
                    Discv5Event::Discovered(enr) => info!("Enr discovered {}", enr),
                    Discv5Event::EnrAdded { enr, replaced: _ } => info!("Enr added {}", enr),
                    Discv5Event::NodeInserted { node_id, replaced: _ } => info!("Node inserted {}", node_id),
                    Discv5Event::SessionEstablished(enr, _) => info!("Session established {}", enr),
                    Discv5Event::SocketUpdated(addr) => info!("Socket updated {}", addr),
                    Discv5Event::TalkRequest(_) => info!("Talk request received"),
                    Discv5Event::NATUpdated(addr) => info!("Node is behind NAT, externally reachable address updated {}", addr),
                    Discv5Event::NATSymmetricUpdated(ip) => info!("Node is behind a symmetric NAT, externally reachable ip updated {}", ip),
                    Discv5Event::SessionEstablishedNat(enr, _) => info!("Session established with node behind NAT {}", enr),
                    Discv5Event::SessionEstablishedNatSymmetric(enr, _, _) => info!("Session established with node behind symmetric NAT {}", enr),
                };
            }
        }
    }
}

pub enum SocketKind {
    Ip4,
    Ip6,
    Ds,
}

impl std::fmt::Display for SocketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketKind::Ip4 => f.write_str("ip4"),
            SocketKind::Ip6 => f.write_str("ip6"),
            SocketKind::Ds => f.write_str("ds"),
        }
    }
}

impl std::str::FromStr for SocketKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ip4" => Ok(SocketKind::Ip4),
            "ip6" => Ok(SocketKind::Ip6),
            "ds" => Ok(SocketKind::Ds),
            _ => Err("bad kind"),
        }
    }
}
