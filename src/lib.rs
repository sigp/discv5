//! The libp2p implemention of [Discovery V5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md).
//!
//! # Overview
//!
//! Discovery v5 is a protocol designed for encrypted peer discovery and topic advertisement. Each peer/node
//! on the network is identified via it's ['ENR'] ([Ethereum Name
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
//!  * Transport - The transport for this protocol is currently fixed to UDP and is realised by the
//!  [`Discv5Service`] struct. It encodes/decodes [`Packet`]'s to and from the specified UDP
//!  socket.
//!  * Session - The protocol's communication is encrypted with `AES_GCM`. All node communication
//!  undergoes a handshake, which results in a [`Session`]. [`Session`]'s are established when
//!  needed and get dropped after a timeout. This section manages the creation and maintenance of
//!  sessions between nodes. It is realised by the [`SessionService`] struct.
//!  * Behaviour - This section contains the protocol-level logic. In particular it manages the
//!  routing table of known ENR's, topic registration/advertisement and performs various qeuries
//!  such as peer discovery. This section is realised by the [`Discv5`] struct.
//!
//!  *Note* -  Currently only `secp256k1` keys are supported.
//!
//! # Usage
//!
//! [`Discv5`] implements the [`NetworkBehaviour`] trait and can therefore be composed as a
//! behaviour on a [`Swarm`].  In order to start a [`Discv5`] service, an [`Enr`] is required. This
//! identifies the node, attributes various values to our node for broadcasting in the discovery
//! protocol. Although an IP can be specified in the ENR, the [`Discv5`] service requires a listen
//! address to allow for listening on multiple interfaces, more specifically, the `0.0.0.0`
//! address. The UDP port will be that of the ENR. If there is no port defined in the ENR, the
//! service creation will fail.
//!
//! A simple example of creating this service is as follows:
//!
//! ```rust
//! use libp2p_core::identity::Keypair;
//! use enr::{Enr,EnrBuilder};
//! use std::net::Ipv4Addr;
//! use libp2p_discv5::{Discv5, Discv5Config};
//! use std::convert::TryInto;
//!
//!   // generate a key for the node
//!   let keypair = Keypair::generate_secp256k1();
//!   let enr_key = keypair.clone().try_into().unwrap();
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
//!     // listen on the udp socket of the enr
//!     let listen_address = enr.udp_socket().unwrap();
//!
//!     // use default settings for the discv5 service
//!     let config = Discv5Config::default();
//!
//!    // construct the discv5 behaviour
//!    // the substream type is removed for demonstrative purposes
//!    let discv5: Discv5<()> = Discv5::new(enr, keypair, config, listen_address).unwrap();
//! ```
//!
//! To see a usage in a swarm environment, see the `discv5` example in `/examples`.
//!
//! [`Enr`]: enr::Enr
//! [`Discv5`]: crate::Discv5
//! [`Discv5Service`]: crate::service::Discv5Service
//! [`NetworkBehaviour`]: libp2p_core::swarm::NetworkBehaviour
//! [`Packet`]: crate::service::Packet
//! [`SessionService`]: crate::session_service::SessionService
//! [`Session`]: crate::session::Session
//! [`Swarm`]: libp2p_core::swarm::Swarm

mod behaviour;
mod config;
mod error;
mod kbucket;
mod packet;
mod query_pool;
mod rpc;
mod service;
mod session;
mod session_service;

pub use behaviour::{Discv5, Discv5Event};
pub use config::{Discv5Config, Discv5ConfigBuilder};
pub use error::Discv5Error;
// re-export the ENR crate
pub use enr;
