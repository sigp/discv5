
use super::packet::{AuthHeader, AuthResponse, AuthTag, Nonce, Packet, Tag, MAGIC_LENGTH};
use crate::Discv5Error;
use enr::{CombinedKey, Enr, NodeId};
use log::debug;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use zeroize::Zeroize;

mod crypto;
mod ecdh_ident;

pub(crate) struct RandomSession {
    /// Requests awaiting the session to be established.
    pending_requests: VecDequeue<Request>

    /// The node that this session connected to.
    node_contact: NodeContact,
}

impl RandomSession {

    /* Session Generation Functions */

    /// Creates a new `Session` instance and generates a RANDOM packet to be sent along with this
    /// session being established. This session is set to `RandomSent` state.
    pub(crate) fn new(node_contact: NodeContact) -> Self {
        RandomSession {
            node_contact,
        };
    }

    /// Converts a `RandomSession` into a `WhoAreYouSession`.
    pub(crate) fn into_whoareyou(self) -> WhoAreYouSession { 
        WhoAreYouSession {
            pending_requests: self.pending_requests,
            node_contact: Some(self.node_contract),
            last_seen_socket: self.last_seen_socket,
        }
    }

    /* Encryption Related Functions */

    /// Consumes self and upgrades to a `Session`.
    pub(crate) fn encrypt_with_header(
        self,
        tag: Tag,
        local_key: &CombinedKey,
        updated_enr: Option<Enr<CombinedKey>>,
        local_node_id: &NodeId,
        id_nonce: &Nonce,
    ) -> Result<(Packet, Session), Discv5Error> {

        // There must be a message to send
        if self.pending_messages.is_empty() {
            Err(Discv5Error::Custom("No message to send in response to a WHOAREYOU"));
        }
        let request = self.pending_requests.remove(0);

        // generate the session keys
        let (encryption_key, decryption_key, auth_resp_key, ephem_pubkey) =
            crypto::generate_session_keys(
                local_node_id,
                &self.node_contact
                id_nonce,
            )?;

        let keys = Keys {
            auth_resp_key,
            encryption_key,
            decryption_key,
        };

        // construct the nonce signature
        let sig = crypto::sign_nonce(local_key, id_nonce, &ephem_pubkey)
            .map_err(|_| Discv5Error::Custom("Could not sign WHOAREYOU nonce"))?;

        // generate the auth response to be encrypted
        let auth_pt = AuthResponse::new(&sig, updated_enr).encode();

        // encrypt the auth response
        let auth_response_ciphertext =
            crypto::encrypt_message(&auth_resp_key, [0u8; 12], &auth_pt, &[])?;

        // generate an auth header, with a random auth_tag
        let auth_tag: [u8; 12] = rand::random();
        let auth_header = AuthHeader::new(
            auth_tag,
            *id_nonce,
            ephem_pubkey.to_vec(),
            auth_response_ciphertext,
        );

        // encrypt the message
        let message_ciphertext =
            crypto::encrypt_message(&encryption_key, auth_tag, request.clone(), &tag[..])?;

        let packet = Packet::AuthMessage {
            tag,
            auth_header,
            message: message_ciphertext,
        };

        let session: Session = self.into()
        Ok((packet, request, session))

    }
}
