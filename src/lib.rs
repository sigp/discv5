#![warn(rust_2018_idioms)]
#![deny(rustdoc::broken_intra_doc_links)]
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
//!  For a simple CLI discovery service see [discv5-cli](https://github.com/AgeManning/discv5-cli)
//!
//! This protocol is split into four main sections/layers:
//!
//!  * Socket - The [`socket`] module is responsible for opening the underlying UDP socket. It
//!  creates individual tasks for sending/encoding and receiving/decoding packets from the UDP
//!  socket.
//!  * Handler - The protocol's communication is encrypted with `AES_GCM`. All node communication
//!  undergoes a handshake, which results in a [`Session`]. [`Session`]'s are established when
//!  needed and get dropped after a timeout. This section manages the creation and maintenance of
//!  sessions between nodes and the encryption/decryption of packets from the socket. It is realised by the [`handler::Handler`] struct and it runs in its own task.
//!  * Service - This section contains the protocol-level logic. In particular it manages the
//!  routing table of known ENR's, topic registration/advertisement and performs various queries
//!  such as peer discovery. This section is realised by the [`Service`] struct. This also runs in
//!  it's own thread.
//!  * Application - This section is the user-facing API which can start/stop the underlying
//!  tasks, initiate queries and obtain metrics about the underlying server.
//!
//!  ## Event Stream
//!
//!  The [`Discv5`] struct provides access to an event-stream which allows the user to listen to
//!  [`Discv5Event`] that get generated from the underlying server. The stream can be obtained
//!  from the [`Discv5::event_stream()`] function.
//!
//!  ## Runtimes
//!
//!  Discv5 requires a tokio runtime with timing and io enabled. An explicit runtime can be given
//!  via the configuration. See the [`Discv5ConfigBuilder`] for further details. Such a runtime
//!  must implement the [`Executor`] trait.
//!
//!  If an explicit runtime is not provided via the configuration parameters, it is assumed that
//!  a tokio runtime is present when creating the [`Discv5`] struct. The struct will use the
//!  existing runtime for spawning the underlying server tasks. If a runtime is not present, the
//!  creation of the [`Discv5`] struct will panic.
//!
//! # Usage
//!
//! A simple example of creating this service is as follows:
//!
//! ```rust
//!    use discv5::{enr, enr::{CombinedKey, NodeId}, TokioExecutor, Discv5, Discv5ConfigBuilder};
//!    use std::net::SocketAddr;
//!
//!    // listening address and port
//!    let listen_addr = "0.0.0.0:9000".parse::<SocketAddr>().unwrap();
//!
//!    // construct a local ENR
//!    let enr_key = CombinedKey::generate_secp256k1();
//!    let enr = enr::EnrBuilder::new("v4").build(&enr_key).unwrap();
//!
//!    // build the tokio executor
//!    let mut runtime = tokio::runtime::Builder::new_multi_thread()
//!        .thread_name("Discv5-example")
//!        .enable_all()
//!        .build()
//!        .unwrap();
//!
//!    // default configuration
//!    let config = Discv5ConfigBuilder::new().build();
//!
//!    // construct the discv5 server
//!    let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();
//!
//!    // In order to bootstrap the routing table an external ENR should be added
//!    // This can be done via add_enr. I.e.:
//!    // discv5.add_enr(<ENR>)
//!
//!    // start the discv5 server
//!    runtime.block_on(discv5.start(listen_addr));
//!
//!    // run a find_node query
//!    runtime.block_on(async {
//!       let found_nodes = discv5.find_node(NodeId::random()).await.unwrap();
//!       println!("Found nodes: {:?}", found_nodes);
//!    });
//! ```
//!
//! [`Discv5`]: struct.Discv5.html
//! [`Discv5Event`]: enum.Discv5Event.html
//! [`Discv5Config`]: config/struct.Discv5Config.html
//! [`Discv5ConfigBuilder`]: config/struct.Discv5ConfigBuilder.html
//! [Packet]: packet/enum.Packet.html
//! [`Service`]: service/struct.Service.html
//! [`Session`]: session/struct.Session.html

mod config;
mod discv5;
mod error;
mod executor;
pub mod handler;
pub mod kbucket;
mod lru_time_cache;
pub mod metrics;
mod node_info;
pub mod packet;
pub mod permit_ban;
mod query_pool;
pub mod rpc;
pub mod service;
pub mod socket;

#[macro_use]
extern crate lazy_static;

pub type Enr = enr::Enr<enr::CombinedKey>;

pub use crate::discv5::{Discv5, Discv5Event};
pub use config::{Discv5Config, Discv5ConfigBuilder};
pub use error::{Discv5Error, QueryError, RequestError, ResponseError};
pub use executor::{Executor, TokioExecutor};
pub use kbucket::{ConnectionDirection, ConnectionState, Key};
pub use permit_ban::PermitBanList;
pub use service::TalkRequest;
pub use socket::{RateLimiter, RateLimiterBuilder};
// re-export the ENR crate
pub use enr;
