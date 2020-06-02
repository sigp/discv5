/// This type relaxes the requirement of having an ENR to connect to a node, to allow for unsigned
/// connection types, such as multiaddrs.
pub enum NodeContact {
    /// We know the ENR of the node we are contacting.
    Enr(Enr)
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
    }
}

impl NodeContact {

    pub fn node_id(&self) -> NodeId {
        match self {
            NodeContact::Enr(enr) => enr.node_id(),
            NodeContact::Raw{ node_address, .. } => node_adress.node_id
        }
    }

    pub fn seq_no(&self) -> Option<u64> {
        match self {
            NodeContact::Enr(enr) => Some(enr.seq_no()),
            _ => None
        }
    }

    pub fn is_enr(&self) -> bool {
        match self {
            Enr(_) => true
                _ => false
        }
    }

    pub fn udp_socket(&self) -> Result<SocketAddr, &'static str> {
        match self {
            Enr(ref enr) => enr.udp_socket().map_err(|_| "ENR does not contain an IP and UDP port")?
            NodeAddress(ref node_address) => node_address.socket_addr.clone()
        }
    }

    pub fn node_address(&self) -> Result<NodeAddress, &'static str> {
        let node_id = self.node_id();
        let socket_addr = self.udp_socket()?;
        NodeAddress {
            node_id,
            socket_addr,
        }
    }
}

/// A representation of an unsigned contactable node.
pub struct NodeAddress {
    /// The destination socket address.
    socket_addr: SocketAddr,
    /// The destination Node Id. 
    node_id: NodeId
}

impl NodeAddress {
    pub fn new(socket_addr: SocketAddr, node_id: NodeId) -> Self {
        Self {
            socket_addr,
            node_id
        }
    }
}
