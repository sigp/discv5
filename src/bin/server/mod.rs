use command::ServerCommand;
use tracing::{info, warn};

use crate::key;

pub mod command;
pub mod enr;

pub async fn run(server_cmd: ServerCommand) -> eyre::Result<()> {
    let key = key::read_secp256k1_key_from_file(&server_cmd.secp256k1_key_file)?;
    let enr = enr::build(&server_cmd, &key)?;

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

    Ok(())
}
