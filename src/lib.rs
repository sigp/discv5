#![warn(rust_2018_idioms)]
#![deny(intra_doc_link_resolution_failure)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::needless_doctest_main)]
//! An implementation of [Discovery V5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md).
//!
//! # Overview
//!
//! Discovery v5 is a protocol designed for encrypted peer discovery and topic advertisement. Each peer/node
//! on the network is identified via it's ENR ([Ethereum Name
//! Record](https://eips.ethereum.org/EIPS/eip-778)), which is essentially a signed key-value store
//! containing the node's public key and optionally IP address and port.
//!
//! Discv5 employs a kademlia-like routing table to store and manage discovered peers and topics. The
//! protocol allows for external IP discovery in NAT environments through regular PING/PONG's with
//! discovered nodes. Nodes return the external IP address that they have received and a simple
//! majority is chosen as our external IP address. If an external IP address is updated, this is
//! produced as an event to notify the swarm (if one is used for this behaviour).
//!
//! This protocol is split into three main sections/layers:
//!
//!  * Transport - The transport for this protocol is currently fixed to UDP and is realised by a
//!  [`Transport`]. It encodes/decodes [Packet]'s to and from the specified UDP
//!  socket.
//!  * Session - The protocol's communication is encrypted with `AES_GCM`. All node communication
//!  undergoes a handshake, which results in a [`Session`]. [`Session`]'s are established when
//!  needed and get dropped after a timeout. This section manages the creation and maintenance of
//!  sessions between nodes. It is realised by the [`Service`] struct.
//!  * Application - This section contains the protocol-level logic. In particular it manages the
//!  routing table of known ENR's, topic registration/advertisement and performs various queries
//!  such as peer discovery. This section is realised by the [`Discv5`] struct.
//!
//!  *Note* -  Currently only `secp256k1` keys are supported.
//!
//!  For a simple CLI discovery service see [discv5-cli](https://github.com/AgeManning/discv5-cli)
//!
//!
//! # Usage
//!
//! The [`Discv5`] service implements `Stream` which emits [`Discv5Event`] events. Running a
//! discv5 service is as simple as initialising a [`Discv5`] struct and driving the stream.
//!
//! The service can be configured via [`Discv5Config`] which can be created using the
//! [`Discv5ConfigBuilder`].
//!
//! A simple example of creating this service is as follows:
//!
//! ```rust
//! use enr::{Enr,EnrBuilder, CombinedKey};
//! use std::net::Ipv4Addr;
//! use discv5::{Discv5, Discv5Config, Discv5Event};
//! use futures::prelude::*;
//!  
//! #[tokio::main]
//! async fn main() {
//!   // generate a key for the node
//!   let enr_key = CombinedKey::generate_secp256k1();
//!
//!   // construct a local ENR
//!   let enr = EnrBuilder::new("v4")
//!        .ip("127.0.0.1".parse::<Ipv4Addr>().expect("valid address").into())
//!        .udp(9000)
//!        .build(&enr_key)
//!        .unwrap();
//!
//!     // display the ENR's node id and base64 encoding
//!     println!("Node Id: {}", enr.node_id());
//!     println!("Base64 ENR: {}", enr.to_base64());
//!
//!     // listen on the UDP socket of the ENR
//!     let listen_address = enr.udp_socket().unwrap();
//!
//!     // use default settings for the discv5 service
//!     let config = Discv5Config::default();
//!
//!    // construct the discv5 service
//!    let mut discv5 = Discv5::new(enr, enr_key, config, listen_address).unwrap();
//!
//!    // add another node's ENR to connect to and join an existing DHT
//!    discv5.add_enr("-IS4QKXYSAtVY5dwZneGdrMnuvjnhG3TQM8P8RHW1ZMbdOBsMfKQoZvEe9PqsYgKAb5afYVffn8iCxptuwUamV98d8IBgmlkgnY0gmlwhAAAAACJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCIyg".parse::<Enr<CombinedKey>>().unwrap());
//!
//!     // search peers closest to a target
//!     let target_random_node_id = enr::NodeId::random();
//!     let request_query_id = discv5.find_node(target_random_node_id);
//!
//!    // poll the stream for the next FindNoeResult event
//!    while let Some(event) = discv5.next().await {
//!        match event {
//!             Discv5Event::FindNodeResult { closer_peers, query_id, .. } => {
//!                 println!("Query with id {} completed. Found {} peers", query_id.0, closer_peers.len());
//!                 break;
//!             }
//!             _ => {} // handle other discv5 events
//!         }
//!    }
//! }
//! ```
//!
//! To see a usage in a runtime environment, see the `find_nodes` example in `/examples`.
//!
//! [`Discv5`]: struct.Discv5.html
//! [`Discv5Event`]: enum.Discv5Event.html
//! [`Discv5Config`]: config/struct.Discv5Config.html
//! [`Discv5ConfigBuilder`]: config/struct.Discv5ConfigBuilder.html
//! [`Transport`]: transport/struct.Transport.html
//! [Packet]: packet/enum.Packet.html
//! [`Service`]: service/struct.Service.html
//! [`Session`]: session/struct.Session.html

mod config;
mod discv5;
mod error;
mod executor;
mod kbucket;
pub mod packet;
mod query_pool;
mod rpc;
pub mod service;
mod session;
mod transport;

pub use crate::discv5::{Discv5, Discv5Event};
pub use config::{Discv5Config, Discv5ConfigBuilder};
pub use error::Discv5Error;
pub use executor::Executor;
// re-export the ENR crate
pub use enr;
pub use query_pool::QueryId;
