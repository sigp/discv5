pub use crate::node_info::{NodeAddress, NodeContact};
use crate::{
    packet::Packet,
    rpc::{Request, RequestId},
};

/// A request to a node that we are waiting for a response.
#[derive(Debug)]
pub(crate) struct RequestCall {
    contact: NodeContact,
    /// The raw discv5 packet sent.
    packet: Packet,
    /// The unencrypted message. Required if need to re-encrypt and re-send.
    request: Request,
    /// Handshakes attempted.
    handshake_sent: bool,
    /// The number of times this request has been re-sent.
    retries: u8,
    /// If we receive a Nodes Response with a total greater than 1. This keeps track of the
    /// remaining responses expected.
    remaining_responses: Option<u64>,
    /// Signifies if we are initiating the session with a random packet. This is only used to
    /// determine the connection direction of the session.
    initiating_session: bool,
}

impl RequestCall {
    pub fn new(
        contact: NodeContact,
        packet: Packet,
        request: Request,
        initiating_session: bool,
    ) -> Self {
        RequestCall {
            contact,
            packet,
            request,
            handshake_sent: false,
            retries: 1,
            remaining_responses: None,
            initiating_session,
        }
    }

    /// Returns the contact associated with this call.
    pub fn contact(&self) -> &NodeContact {
        &self.contact
    }

    /// Returns the id associated with this call.
    pub fn id(&self) -> &RequestId {
        &self.request.id
    }

    /// Returns the associated request for this call.
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Returns the packet associated with this call.
    pub fn packet(&self) -> &Packet {
        &self.packet
    }

    /// The number of times this request has been resent.
    pub fn retries(&self) -> u8 {
        self.retries
    }

    /// Increments the number of retries for this call
    pub fn increment_retries(&mut self) {
        self.retries += 1;
    }

    /// Returns whether the handshake has been sent for this call or not.
    pub fn handshake_sent(&self) -> bool {
        self.handshake_sent
    }

    /// Indicates the handshake has been sent.
    pub fn set_handshake_sent(&mut self) {
        self.handshake_sent = true;
    }

    /// Indicates a session has been initiated for this call.
    pub fn set_initiating_session(&mut self, state: bool) {
        self.initiating_session = state;
    }

    /// Returns whether a session is being initiated for this call.
    pub fn initiating_session(&self) -> bool {
        self.initiating_session
    }

    /// Updates the underlying packet for the call.
    pub fn update_packet(&mut self, packet: Packet) {
        self.packet = packet;
    }

    /// Gets a mutable reference to the remaining repsonses.
    pub fn remaining_responses_mut(&mut self) -> &mut Option<u64> {
        &mut self.remaining_responses
    }
}
