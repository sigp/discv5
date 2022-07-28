use super::*;

/// The maximum number of NODES responses we allow at the handler level.
const MAX_NODES_RESPONSES: u64 = 5;

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
    /// A NODES response can span multiple datagrams. If we are receiving multiple NODES responses,
    /// this tracks the number of datagrams we are still expecting.
    awaiting_nodes: Option<u64>,
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
            awaiting_nodes: None,
            initiating_session,
        }
    }

    /// Increments the retry count.
    pub fn retry(&mut self) {
        self.retries = self.retries.saturating_add(1);
    }

    /// We are now sending an authentication response to the node. The packet is being upgraded to
    /// an authentication packet.
    pub fn upgrade_to_auth_packet(&mut self, packet: Packet) {
        self.packet = packet;
        self.handshake_sent = true;
    }

    /// Sets the initiating_session flag.
    pub fn set_initiating_session(&mut self, initiating_session: bool) {
        self.initiating_session = initiating_session;
    }

    /// We have received a NODES response, with a given total.
    /// If we require further messages, update the state of the [`RequestCall`]. If this request
    /// has more messages to be received, this function returns true.
    pub fn register_nodes_response(&mut self, total: u64) -> bool {
        if total > 1 && total <= MAX_NODES_RESPONSES {
            if let Some(mut remaining) = self.awaiting_nodes {
                remaining = remaining.saturating_sub(1);
                if remaining == 0 {
                    // Change the state so that `register_ticket` can be informed we are no longer
                    // waiting for messages
                    self.awaiting_nodes = None;
                } else {
                    return true; // still waiting for more messages
                }
            } else {
                // This is the first instance
                self.awaiting_nodes = Some(total - 1);
                return true; // still waiting for more messages
            }
        }
        false // This was a single NODES response and we have no interest in waiting for more messages.
    }

    /// Returns the request ID associated with the [`RequestCall`].
    pub fn id(&self) -> &RequestId {
        &self.request.id
    }

    /// Returns the raw request.
    pub fn raw_request(&self) -> &Request {
        &self.request
    }

    /// Returns the raw packet of the request
    pub fn packet(&self) -> &Packet {
        &self.packet
    }

    /// The destination contact for this request.
    pub fn contact(&self) -> &NodeContact {
        &self.contact
    }

    /// Returns the [`RequestBody`] associated with the [`RequestCall`].
    pub fn kind(&self) -> &RequestBody {
        &self.request.body
    }

    /// Returns the number of retries this request has undertaken.
    pub fn retries(&self) -> u8 {
        self.retries
    }

    /// Whether we have sent a handshake or not.
    pub fn handshake_sent(&self) -> bool {
        self.handshake_sent
    }

    /// Whether our node is the one that is initiating the session.
    pub fn initiating_session(&self) -> bool {
        self.initiating_session
    }
}
