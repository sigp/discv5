use clap::{command, Parser};
use std::{net::Ipv4Addr, path::PathBuf};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct ServerArgs {
    /// Specify a secp256k1 private key file (hex encoded) to use for the nodes identity.
    #[clap(
        long = "secp256k1-key-file",
        help = "Specify a secp256k1 private key file (hex encoded) to use for the nodes identity."
    )]
    pub secp256k1_key_file: PathBuf,

    /// Specifies the listening address of the server.
    #[clap(long = "listen.ipv4", default_value = "0.0.0.0")]
    pub listen_ipv4: Ipv4Addr,

    /// Specifies the listening UDP port of the server.
    #[clap(long = "listen.port", default_value = "9000")]
    pub listen_port: u16,

    /// Specifies the IP address of the ENR record. Not specifying this results in an ENR with no IP field.
    #[clap(long = "advertise.ipv4")]
    pub advertise_ipv4: Option<Ipv4Addr>,

    /// Specifies the UDP port of the ENR record. Not specifying this results in an ENR with no UDP field.
    #[clap(long = "advertise.port")]
    pub advertise_port: Option<u16>,

    /// Specifies an ipv4 network range of addresses, e.g 10.42.0.0/15 is 10.42.0.0 - 10.43.255.255. This allows peers which are advertising on a public IP but within the same subnet to be added to the discovery table
    #[clap(long = "cidr")]
    pub cidr: Option<cidr::Ipv4Cidr>,

    /// Address for enr echo server
    #[clap(long = "rpc.addr", default_value = "0.0.0.0")]
    pub rpc_addr: Ipv4Addr,

    /// Port for enr echo server
    #[clap(long = "rpc.port", default_value = "8080")]
    pub rpc_port: u16,
}
