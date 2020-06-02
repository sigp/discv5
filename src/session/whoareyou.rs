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
}

impl WhoAreYouSession {
    /* Session Generation Functions */

    /// Creates a new `Session` and generates an associated WHOAREYOU packet. The returned session is in the
    /// `WhoAreYouSent` state.
    pub(crate) fn new_whoareyou(node_contact: Option<NodeContact>) -> Self {
        WhoAreYouSession {
            pending_requests: vec![],
            node_contact,
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

        let 
        // session has been established
        self.state = SessionState::Established(keys);

        // output if the session is trusted or untrusted
        Ok(self.update_trusted())
    }
}
