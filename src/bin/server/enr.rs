use discv5::enr;

use super::args::ServerArgs;

pub fn build(
    args: &ServerArgs,
    enr_key: &enr::CombinedKey,
) -> eyre::Result<enr::Enr<enr::CombinedKey>> {
    let mut builder = enr::Builder::default();

    builder.ip4(args.listen_ipv4).udp4(args.listen_port);

    if let Some(port) = &args.advertise_port {
        builder.udp4(*port);
    }

    if let Some(advertise_ipv4) = &args.advertise_ipv4 {
        builder.ip4(*advertise_ipv4);
    }

    let enr = builder.build(enr_key)?;

    Ok(enr)
}
