use std::net::SocketAddr;

use enr::NodeId;

use crate::{
    node_info::NodeAddress, packet::MessageNonce, rpc::Notification, Enr, ProtocolIdentity,
};

mod error;
mod utils;

pub use error::Error;
pub use utils::NatUtils;

#[async_trait::async_trait]
pub trait HolePunchNat {
    /// A request times out. Should trigger the initiation of a hole punch attempt, given a
    /// transitive route to the target exists. Sends a RELAYINIT notification to the given
    /// relay.
    async fn on_request_time_out<P: ProtocolIdentity>(
        &mut self,
        relay: NodeAddress,
        local_enr: Enr, // initiator-enr
        timed_out_nonce: MessageNonce,
        target_node_address: NodeAddress,
    ) -> Result<(), Error>;

    /// A RelayInit notification is received over discv5 indicating this node is the relay. Should
    /// trigger sending a RelayMsg to the target.
    async fn on_relay_init(
        &mut self,
        initr: Enr,
        tgt: NodeId,
        timed_out_nonce: MessageNonce,
    ) -> Result<(), Error>;

    /// A RelayMsg notification is received over discv5 indicating this node is the target. Should
    /// trigger a WHOAREYOU to be sent to the initiator using the `nonce` in the RelayMsg.
    async fn on_relay_msg(
        &mut self,
        initr: Enr,
        timed_out_nonce: MessageNonce,
    ) -> Result<(), Error>;

    /// Send a RELAYMSG notification.
    async fn send_relay_msg_notif<P: ProtocolIdentity>(
        &mut self,
        tgt_enr: Enr,
        relay_msg_notif: Notification,
    ) -> Result<(), Error>;

    /// A hole punched for a peer closes. Should trigger an empty packet to be sent to the
    /// peer to keep it open.
    async fn on_hole_punch_expired(&mut self, peer: SocketAddr) -> Result<(), Error>;
}
