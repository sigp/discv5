use args::ServerArgs;
use discv5::{ConfigBuilder, DefaultProtocolId, Discv5, Event, ListenConfig};
use std::error::Error;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::key;

pub mod args;
pub mod enr;
pub mod stats;

pub async fn run(args: ServerArgs) -> Result<(), Box<dyn Error>> {
    let key = key::read_secp256k1_key_from_file(&args.secp256k1_key_file)?;
    let enr = enr::build(&args, &key)?;

    info!("Node Id: {}", enr.node_id());
    if enr.udp4_socket().is_some() {
        info!("Base64 ENR: {}", enr.to_base64());
        info!(
            "ip: {}, udp port:{}",
            enr.ip4().unwrap(),
            enr.udp4().unwrap()
        );
    } else {
        warn!("ENR is not printed as no IP:PORT was specified");
    }

    let listen_config = ListenConfig::Ipv4 {
        ip: args.listen_ipv4,
        port: args.listen_port,
    };

    let mut config = ConfigBuilder::new(listen_config);

    if let Some(cidr) = &args.cidr {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        let local_addr = socket.local_addr()?;

        match local_addr.ip() {
            std::net::IpAddr::V4(ip) => {
                if cidr.contains(&ip) {
                    info!("Found ip {:?} within cidr: {:?}, allowing automatic discovery table addition for source addresses under this range", ip, cidr);
                    config.allowed_cidr(cidr);
                } else {
                    warn!(
                        "added --cidr flag but local ip ({:?}) is not contained within range: {:?}",
                        ip, cidr
                    )
                }
            }
            std::net::IpAddr::V6(_) => {
                warn!("allowed cidr only compatible with ipv4")
            }
        };
    }

    info!(
        "Server listening on {:?}:{:?}",
        args.listen_ipv4, args.listen_port
    );
    let mut discv5: Discv5<DefaultProtocolId> = Discv5::new(
        enr,
        key,
        config
            .request_timeout(Duration::from_secs(3))
            .vote_duration(Duration::from_secs(120))
            .build(),
    )?;

    discv5
        .start()
        .await
        .expect("Should be able to start the server");
    let server_ref = Arc::new(discv5);
    stats::run(Arc::clone(&server_ref), None, 100);

    let mut event_stream = server_ref.event_stream().await.unwrap();
    loop {
        match event_stream.recv().await {
            Some(Event::SocketUpdated(addr)) => {
                info!("Nodes ENR socket address has been updated to: {:?}", addr);
            }
            Some(Event::Discovered(enr)) => {
                info!("A peer has been discovered: {}", enr.node_id());
            }
            Some(Event::UnverifiableEnr { enr, .. }) => {
                info!(
                    "A peer has been added to the routing table with enr: {}",
                    enr
                );
            }
            Some(Event::NodeInserted { node_id, .. }) => {
                info!(
                    "A peer has been added to the routing table with node_id: {}",
                    node_id
                );
            }
            Some(Event::SessionEstablished(enr, addr)) => {
                info!(
                    "A session has been established with peer: {} at address: {}",
                    enr, addr
                );
            }
            Some(Event::TalkRequest(talk_request)) => {
                info!(
                    "A talk request has been received from peer: {}",
                    talk_request.node_id()
                );
            }
            _ => {}
        }
    }
}
