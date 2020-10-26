discv5
============

[![Build Status]][Build Link] [![Doc Status]][Doc Link] [![Crates
Status]][Crates Link]

[Build Status]: https://github.com/sigp/discv5/workflows/build/badge.svg?branch=master
[Build Link]: https://github.com/sigp/discv5/actions
[Doc Status]: https://docs.rs/discv5/badge.svg
[Doc Link]: https://docs.rs/discv5
[Crates Status]: https://img.shields.io/crates/v/discv5.svg
[Crates Link]: https://crates.io/crates/discv5

[Documentation at docs.rs](https://docs.rs/discv5)


# Overview

This is a rust implementation of the [Discovery v5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md)
peer discovery protocol.

Discovery v5 is a protocol designed for encrypted peer discovery and topic advertisement. Each peer/node
on the network is identified via it's `ENR` ([Ethereum Node
Record](https://eips.ethereum.org/EIPS/eip-778)), which is essentially a signed key-value store
containing the node's public key and optionally IP address and port.

Discv5 employs a kademlia-like routing table to store and manage discovered peers and topics. The
protocol allows for external IP discovery in NAT environments through regular PING/PONG's with
discovered nodes. Nodes return the external IP address that they have received and a simple
majority is chosen as our external IP address. If an external IP address is updated, this is
produced as an event to notify the swarm (if one is used for this behaviour).

For a simple CLI discovery service see [discv5-cli](https://github.com/AgeManning/discv5-cli)

# Usage

A simple example of creating this service is as follows:

```rust
   use discv5::{enr, enr::{CombinedKey, NodeId}, TokioExecutor, Discv5, Discv5ConfigBuilder};
   use std::net::SocketAddr;

   // listening address and port
   let listen_addr = "0.0.0.0:9000".parse::<SocketAddr>().unwrap();

   // construct a local ENR
   let enr_key = CombinedKey::generate_secp256k1();
   let enr = enr::EnrBuilder::new("v4").build(&enr_key).unwrap();

   // build the tokio executor
   let mut runtime = tokio::runtime::Builder::new_multi_thread()
       .thread_name("Discv5-example")
       .enable_all()
       .build()
       .unwrap();

   // default configuration
   let config = Discv5ConfigBuilder::new().build();

   // construct the discv5 server
   let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();

   // In order to bootstrap the routing table an external ENR should be added
   // This can be done via add_enr. I.e.:
   // discv5.add_enr(<ENR>)

   // start the discv5 server
   runtime.block_on(discv5.start(listen_addr));

   // run a find_node query
   runtime.block_on(async {
      let found_nodes = discv5.find_node(NodeId::random()).await.unwrap();
      println!("Found nodes: {:?}", found_nodes);
   });
```
