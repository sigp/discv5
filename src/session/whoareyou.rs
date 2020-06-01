use super::packet::{AuthHeader, AuthResponse, AuthTag, Nonce, Packet, Tag, MAGIC_LENGTH};
use crate::Discv5Error;
use enr::{CombinedKey, Enr, NodeId};
use log::debug;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use zeroize::Zeroize;

mod crypto;
mod ecdh_ident;

pub(crate) struct WhoAreYouSession {
    /// Requests awaiting the session to be established.
    pending_requests: VecDequeue<Request>,

    node_contact: Option<NodeContact>,

    /// Last seen IP address and port. This is used to determine if the session is trusted or not.
    last_seen_socket: Option<SocketAddr>,
}

impl WhoAreYouSession {
    /* Session Generation Functions */

    /// Creates a new `Session` and generates an associated WHOAREYOU packet. The returned session is in the
    /// `WhoAreYouSent` state.
    pub(crate) fn new_whoareyou(node_contact: Option<NodeContact>) -> Self {
        WhoAreYouSession {
            pending_requests: vec![],
            last_seen_socket: None,
        }
    }

    /// Generates session keys from an authentication header. If the IP of the ENR does not match the
    /// source IP address, we consider this session untrusted. The output returns a boolean which
    /// specifies if the Session is trusted or not.
    pub(crate) fn establish_from_header(
        &mut self,
        local_key: &CombinedKey,
        local_id: &NodeId,
        remote_id: &NodeId,
        id_nonce: Nonce,
        auth_header: &AuthHeader,
    ) -> Result<bool, Discv5Error> {
        // generate session keys
        let (decryption_key, encryption_key, auth_resp_key) = crypto::derive_keys_from_pubkey(
            local_key,
            local_id,
            remote_id,
            &id_nonce,
            &auth_header.ephemeral_pubkey,
        )?;

        // decrypt the authentication header
        let auth_response = crypto::decrypt_authentication_header(&auth_resp_key, auth_header)?;

        // check and verify a potential ENR update
        if let Some(enr) = auth_response.node_record {
            if let Some(remote_enr) = &self.remote_enr {
                // verify the enr-seq number
                if remote_enr.seq() < enr.seq() {
                    self.remote_enr = Some(enr);
                } // ignore ENR's that have a lower seq number
            } else {
                // update the ENR
                self.remote_enr = Some(enr);
            }
        } else if self.remote_enr.is_none() {
            // didn't receive the remote's ENR
            return Err(Discv5Error::InvalidEnr);
        }

        // ENR must exist here
        let remote_public_key = self
            .remote_enr
            .as_ref()
            .expect("ENR Must exist")
            .public_key();
        // verify the auth header nonce
        if !crypto::verify_authentication_nonce(
            &remote_public_key,
            &auth_header.ephemeral_pubkey,
            &id_nonce,
            &auth_response.signature,
        ) {
            return Err(Discv5Error::InvalidSignature);
        }

        let keys = Keys {
            auth_resp_key,
            encryption_key,
            decryption_key,
        };

        // session has been established
        self.state = SessionState::Established(keys);

        // output if the session is trusted or untrusted
        Ok(self.update_trusted())
    }

    /// Updates the trusted status of a Session. It can be promoted to an `established` state, or
    /// demoted to an `untrusted` state. This value returns true if the Session has been
    /// promoted.
    pub(crate) fn update_trusted(&mut self) -> bool {
        if let TrustedState::Untrusted = self.trusted {
            if let Some(remote_enr) = &self.remote_enr {
                if Some(self.last_seen_socket) == remote_enr.udp_socket() {
                    self.trusted = TrustedState::Trusted;
                    return true;
                }
            }
        } else if let TrustedState::Trusted = self.trusted {
            if let Some(remote_enr) = &self.remote_enr {
                if Some(self.last_seen_socket) != remote_enr.udp_socket() {
                    self.trusted = TrustedState::Untrusted;
                }
            }
        }
        false
    }

    /// The socket address of the last packer received from this node.
    pub(crate) fn set_last_seen_socket(&mut self, socket: SocketAddr) {
        self.last_seen_socket = socket;
    }

    pub(crate) fn is_whoareyou_sent(&self) -> bool {
        SessionState::WhoAreYouSent == self.state
    }

    pub(crate) fn is_random_sent(&self) -> bool {
        SessionState::RandomSent == self.state
    }

    pub(crate) fn is_awaiting_response(&self) -> bool {
        if let SessionState::AwaitingResponse(_) = self.state {
            true
        } else {
            false
        }
    }

    pub(crate) fn remote_enr(&self) -> &Option<Enr<CombinedKey>> {
        &self.remote_enr
    }

    pub(crate) fn is_trusted(&self) -> bool {
        if let TrustedState::Trusted = self.trusted {
            true
        } else {
            false
        }
    }

    /// Returns true if the Session is trusted and has established session keys. This state means
    /// the session is capable of sending requests.
    pub(crate) fn trusted_established(&self) -> bool {
        let established = match &self.state {
            SessionState::WhoAreYouSent => false,
            SessionState::RandomSent => false,
            SessionState::AwaitingResponse(_) => false,
            SessionState::Established(_) => true,
            SessionState::EstablishedAwaitingResponse { .. } => true,
            SessionState::Poisoned => unreachable!(),
        };

        self.is_trusted() && established
    }
}
