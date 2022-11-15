//! Contains a collection of types used to handle the various forms of connections that can be
//! established.

use std::net::SocketAddr;

/// Describes a type of connection, i.e its direction and any additional NAT properties.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct Connection {
    /// The direction of the connection.
    pub direction: ConnectionDirection,
    /// The socket address that corresponds to the connection
    pub socket: SocketAddr,
    /// The type of connection made.
    pub nat_kind: NatKind,
}

impl Connection {
    /// Returns true if the connection direction is incoming.
    pub fn is_incoming(&self) -> bool {
        matches!(self.direction, ConnectionDirection::Incoming)
    }
}

/// The kind of connection that has been established.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum NatKind {
    /// This connection is a direct connection, without any additional NAT issues.
    Direct,
    /// Represents a connection with a peer behind a NAT. This can occur via the peer
    /// simply dialing out to this node, via the NAT traversal protocol.
    ///
    /// A connection with a peer behind a NAT is only considered established once we have
    /// received an ENR from the peer and the observed `SocketAddr` matches the one declared in
    /// the 'nat'/'nat6' and 'udp'/'udp6' fields of the ENR.
    ///
    /// The [`ConnectionDirection`] is incoming if the peer dialed out to us directly without use
    /// of the NAT traversal protocol. This peer will send PINGs to this node more frequently than
    /// nodes that are not behind a NAT do, this way the hole punched in the peer's NAT for this
    /// node will stay open and this peer can listen for requests from this node.
    ///
    /// Using the NAT traversal protocol to get the peer to dial out to us will always result in a
    /// [`ConnectionDirection::Outgoing`] direction for both parties, the initiator and the
    /// receiver. The initiator learns about the receiver in a NODES response from the rendezvous
    /// node and attempts to connect to it via the rendezvous node. The receiver learns about the
    /// initiator in a RELAYREQUEST from the rendezvous node and dials out to the initiator (this
    /// first message is dropped by the initiator if it is also behind a NAT).
    FullCone,
    /// This represents a connection with a peer behind a symmetric NAT.
    ///
    /// A connection with a peer behind a symmetric NAT is only considered established once we have
    /// received an ENR from the node and the observed `IpAddr` matches the one declared in the
    /// 'nat'/'nat6' field of the ENR.
    ///
    /// The [`ConnectionDirection`] is always [`ConnectionDirection::Incoming`] as peers behind
    /// symmetric NATs only dial out. This peer will send PINGs to this node more frequently than
    /// nodes that are not behind a NAT do, this way the hole punched in the peer's NAT for this
    /// node will stay open and this peer can listen for requests from this node.
    ///
    /// Peers behind symmetric NATs cannot be hole-punched as they cannot advertise a port for
    /// new peers to hole-punch them on. The [`ConnectionDirection`] is always incoming as peers
    /// behind symmetric NATs only dial out.
    Symmetric,
}

/// The connection state of a node.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ConnectionState {
    /// The node is connected.
    Connected,
    /// The node is considered disconnected.
    Disconnected,
    /// The node is connected via a symmetric NAT connection. This state, stores the connection
    /// port.
    ConnectedSymmetricNat(u16),
}

/// Whether the connection has been formed from an inbound or outbound initiating connection.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ConnectionDirection {
    /// The node contacted us.
    Incoming,
    /// We contacted the node.
    Outgoing,
}

impl std::fmt::Display for ConnectionDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ConnectionDirection::Incoming => write!(f, "Incoming"),
            ConnectionDirection::Outgoing => write!(f, "Outgoing"),
        }
    }
}

impl std::fmt::Display for NatKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Direct => write!(f, "Direct"),
            Self::FullCone => write!(f, "Full Cone"),
            Self::Symmetric => write!(f, "Symmetric"),
        }
    }
}

impl std::fmt::Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Direction: {}, Socket Address: {}, Nat Kind: {}",
            self.direction, self.socket, self.nat_kind
        )
    }
}
