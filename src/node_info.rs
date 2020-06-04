use super::*;
use crate::Enr;
use enr::{CombinedPublicKey, NodeId};
use std::net::SocketAddr;

/// This type relaxes the requirement of having an ENR to connect to a node, to allow for unsigned
/// connection types, such as multiaddrs.
#[derive(Clone, Debug)]
pub enum NodeContact {
    /// We know the ENR of the node we are contacting.
    Enr(Enr),
    /// We don't have an ENR, but have enough information to start a handshake.
    ///
    /// The handshake will request the ENR at the first opportunity.
    /// The public key can be derived from multiaddr's whose keys can be inlined. The `TryFrom`
    /// implementation for `String` and `MultiAddr`.
    Raw {
        /// An ENR compatible public key, required for handshaking with peers.
        public_key: CombinedPublicKey,
        /// The socket address and ModeId of the peer to connect to.
        node_address: NodeAddress,
    },
}

impl NodeContact {
    pub fn node_id(&self) -> NodeId {
        match self {
            NodeContact::Enr(enr) => enr.node_id(),
            NodeContact::Raw { node_address, .. } => node_address.node_id,
        }
    }

    pub fn seq_no(&self) -> Option<u64> {
        match self {
            NodeContact::Enr(enr) => Some(enr.seq_no()),
            _ => None,
        }
    }

    pub fn is_enr(&self) -> bool {
        match self {
            NodeContact::Enr(_) => true,
            _ => false,
        }
    }

    pub fn udp_socket(&self) -> Result<SocketAddr, &'static str> {
        match self {
            NodeContact::Enr(ref enr) => enr
                .udp_socket()
                .map_err(|_| "ENR does not contain an IP and UDP port")?,
            NodeContact::Raw { node_address, .. } => node_address.socket_addr.clone(),
        }
    }

    pub fn node_address(&self) -> Result<NodeAddress, &'static str> {
        let node_id = self.node_id();
        let socket_addr = self.udp_socket()?;
        Ok(NodeAddress {
            node_id,
            socket_addr,
        })
    }
}

impl From<Enr> for NodeContact {
    fn from(enr: Enr) -> Self {
        NodeContact::Enr(enr)
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
        return self.socket_addr.port().cmp(&other.socket_addr.port());
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
}

impl std::fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node: {}, addr: {:?}", self.node_id, self.socket_addr)
    }
}
