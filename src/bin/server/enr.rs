use std::net::Ipv4Addr;

use discv5::enr;

use super::command::ServerCommand;

pub fn build(
    server: &ServerCommand,
    enr_key: &enr::CombinedKey,
) -> eyre::Result<enr::Enr<enr::CombinedKey>> {
    let mut builder = enr::Builder::default();

    let listen_addr = server.listen_ipv4.parse::<Ipv4Addr>()?;
    let listen_port = server.listen_port;
    builder.ip4(listen_addr).udp4(listen_port);

    if let Some(port) = &server.advertise_port {
        builder.udp4(*port);
    }

    if let Some(addr) = &server.advertise_ipv4 {
        let advertise_ip = addr.parse::<Ipv4Addr>()?;
        builder.ip4(advertise_ip);
    }

    let enr = builder.build(enr_key)?;

    Ok(enr)
}
