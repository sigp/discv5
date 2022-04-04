use super::*;
use crate::Enr;
use enr::{CombinedPublicKey, NodeId};
use std::net::SocketAddr;

#[cfg(feature = "libp2p")]
use libp2p_core::{identity::PublicKey, multiaddr::Protocol, multihash, Multiaddr};

/// This type relaxes the requirement of having an ENR to connect to a node, to allow for unsigned
/// connection types, such as multiaddrs.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeContact {
    /// An ENR compatible public key, required for handshaking with peers.
    public_key: Box<CombinedPublicKey>,
    /// The socket address and `NodeId` of the peer to connect to.
    /// TODO: why do we need the node_id if we have the key?
    node_address: Box<NodeAddress>,
    /// Enr of the node if known.
    /// TODO: reduce size somehow?
    enr: Option<Enr>,
}

impl NodeContact {
    pub fn node_id(&self) -> NodeId {
        self.node_address.node_id
    }

    pub fn public_key(&self) -> CombinedPublicKey {
        *self.public_key.clone()
    }

    pub fn is_enr(&self) -> bool {
        self.enr.is_some()
    }

    pub fn udp_socket(&self) -> SocketAddr {
        self.node_address.socket_addr
    }

    pub fn node_address(&self) -> NodeAddress {
        *self.node_address.clone()
    }

    pub fn enr(&self) -> Option<Enr> {
        self.enr.as_ref().cloned()
    }
}

impl std::convert::TryFrom<Enr> for NodeContact {
    type Error = &'static str;

    fn try_from(enr: Enr) -> Result<Self, Self::Error> {
        let node_address = NodeAddress::from_enr(&enr)?;
        let public_key = enr.public_key();
        Ok(NodeContact {
            public_key: Box::new(public_key),
            node_address: Box::new(node_address),
            enr: Some(enr),
        })
    }
}

#[cfg(feature = "libp2p")]
impl std::convert::TryFrom<Multiaddr> for NodeContact {
    type Error = &'static str;

    fn try_from(multiaddr: Multiaddr) -> Result<Self, Self::Error> {
        // The multiaddr must contain either the ip4 or ip6 protocols, the UDP protocol and the P2P
        // protocol with either secp256k1 or ed25519 keys.

        // perform a single pass and try to fill all required protocols from the multiaddr
        let mut ip_addr = None;
        let mut udp_port = None;
        let mut p2p = None;

        for protocol in multiaddr.into_iter() {
            match protocol {
                Protocol::Udp(port) => udp_port = Some(port),
                Protocol::Ip4(addr) => ip_addr = Some(addr.into()),
                Protocol::Ip6(addr) => ip_addr = Some(addr.into()),
                Protocol::P2p(multihash) => p2p = Some(multihash),
                _ => {}
            }
        }

        let udp_port = udp_port.ok_or("A UDP port must be specified in the multiaddr")?;
        let ip_addr = ip_addr.ok_or("An IP address must be specified in the multiaddr")?;
        let multihash = p2p.ok_or("The p2p protocol must be specified in the multiaddr")?;

        // verify the correct key type
        if multihash.code() != u64::from(multihash::Code::Identity) {
            return Err("The key type is unsupported");
        }

        let public_key: CombinedPublicKey =
            match PublicKey::from_protobuf_encoding(&multihash.to_bytes()[2..])
                .map_err(|_| "Invalid public key")?
            {
                PublicKey::Secp256k1(pk) => {
                    // TODO: Remove libp2p dep to avoid conversion here
                    enr::k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk.encode_uncompressed())
                        .expect("Libp2p key conversion, always valid")
                        .into()
                }
                PublicKey::Ed25519(pk) => enr::ed25519_dalek::PublicKey::from_bytes(&pk.encode())
                    .expect("Libp2p key conversion, always valid")
                    .into(),
                _ => return Err("The key type is not supported"),
            };

        Ok(NodeContact {
            public_key: Box::new(public_key.clone()),
            node_address: Box::new(NodeAddress {
                socket_addr: SocketAddr::new(ip_addr, udp_port),
                node_id: public_key.into(),
            }),
            enr: None,
        })
    }
}

impl std::fmt::Display for NodeContact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "addr: {:?}", self.node_address())
    }
}

/// A representation of an unsigned contactable node.
#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub struct NodeAddress {
    /// The destination socket address.
    pub socket_addr: SocketAddr,
    /// The destination Node Id.
    pub node_id: NodeId,
}

impl Ord for NodeAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let ord = self.node_id.raw().cmp(&other.node_id.raw());
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
        let ord = self.socket_addr.ip().cmp(&other.socket_addr.ip());
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
        self.socket_addr.port().cmp(&other.socket_addr.port())
    }
}

impl PartialOrd for NodeAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl NodeAddress {
    pub fn new(socket_addr: SocketAddr, node_id: NodeId) -> Self {
        Self {
            socket_addr,
            node_id,
        }
    }

    pub fn from_enr(enr: &Enr) -> Result<Self, &'static str> {
        let socket_addr = enr.udp_socket().ok_or("Enr is not contactable")?;
        let node_id = enr.node_id();
        Ok(NodeAddress {
            socket_addr,
            node_id,
        })
    }
}

impl std::fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node: {}, addr: {:?}", self.node_id, self.socket_addr)
    }
}
