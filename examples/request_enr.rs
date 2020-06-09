//! Creates a Discv5 Server and requests an ENR of a node given a multiaddr.
//!
//! This is a simple example of how one may connect to a Discv5 peer using a multiaddr/multiaddr
//! string.
//!
//! To run this example execute the following command from the root directory:
//! ```bash
//! $ cargo run --example request_enr <MULTIADDR>
//! ```
//!
//! The <MULTIADDR> value should be the string form of a multiaddr including the p2p protocol.
//! Currently only secp256k1 and ed25519 keys are supported.
//!
//! This requires the "libp2p" feature.

use discv5::{enr, enr::CombinedKey, Discv5, Discv5Config};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    env_logger::init();

    // listening address and port
    let listen_addr = "0.0.0.0:9000".parse::<SocketAddr>().unwrap();

    // generate a new enr key
    let enr_key = CombinedKey::generate_secp256k1();
    // construct a local ENR
    let enr = enr::EnrBuilder::new("v4").build(&enr_key).unwrap();

    // default discv5 configuration
    let config = Discv5Config::default();

    let multiaddr = std::env::args()
        .nth(1)
        .expect("A multiaddr must be supplied");

    // construct the discv5 server
    let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();

    // start the discv5 service
    discv5.start(listen_addr);

    // search for the ENR
    match discv5.request_enr(multiaddr).await {
        Ok(Some(enr)) => {
            println!("ENR Found:");
            println!("Base64:{}", enr.to_base64());
            println!("{}", enr);
        }
        Ok(None) => {
            println!("No ENR response");
        }
        Err(e) => {
            println!("Error:{:?}", e);
        }
    }
}
