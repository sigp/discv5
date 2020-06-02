//! An [`EstablishingSession`] handles the stages of creating and establishing a handshake with a
//! peer.
//!
//! There are two ways a Session can get initialised.
//!
//! - An RPC request to an unknown peer is requested by the application. In this scenario, a RANDOM packet is sent to the unknown peer. This session is created using the `new_random()` function.
//! - A message was received from an unknown peer and we start the `Session` by sending a
//! WHOAREYOU message.
//!
//! An [`EstablishingSession`] is responisble for holding pending requests and waiting until it
//! can be promoted to an "established" `Session`.
//!
//! [`EstablishingSession`]: struct.EstablishingSession.html

use super::packet::{AuthHeader, AuthResponse, AuthTag, Nonce, Packet, Tag, MAGIC_LENGTH};
use crate::Discv5Error;
use enr::{CombinedKey, Enr, NodeId};
use log::debug;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use zeroize::Zeroize;

mod crypto;
mod ecdh_ident;


/// Manages active handshakes and connections between nodes in discv5. There are three main states
/// a session can be in, initializing (`WhoAreYouSent` or `RandomSent`), `Untrusted` (when the
/// socket address of the ENR doesn't match the `last_seen_socket`) and `Established` (the session
/// has been successfully established).
pub(crate) struct EstablishingSession {
    /// Requests awaiting the session to be established.
    pending_requests: VecDequeue<Request>

    /// The state of the establishing session.
    state: EstablishingSessionState

    /// Last seen IP address and port. This is used to determine if the session is trusted or not.
    last_seen_socket: SocketAddr,
}

#[derive(PartialEq)]
/// The current state of the session. This enum holds the encryption keys for various states.
pub(crate) enum SessionState {

    /// A RANDOM packet has been sent and the Session is awaiting a WHOAREYOU response. A
    /// `NodeContact` is required for this state.
    RandomSent(NodeContact),

    /// A WHOAREYOU packet has been sent, and the Session is awaiting an Authentication response.
    WhoAreYouSent(Option<NodeContact>),

    /// An AuthMessage has been sent with a new set of generated keys. Once a response has been
    /// received that we can decrypt, the session transitions to an established Session, replacing
    AwaitingResponse(NodeContact, Keys),

    /// An `AwaitingResponse` Session has received a WHOAREYOU. In this state, messages are sent
    /// out with the established session keys and new encrypted messages are first attempted to
    /// be decrypted with the established session keys, upon failure, the new keys are tried. If
    /// the new keys are successful, the session keys are updated and the state progresses to
    /// `Established`.
    ReEstablishedAwaitingResponse {
        contact: NodeContact,
        /// The keys used in the current established session.
        current_keys: Keys,
        /// New keys generated from a recent WHOARYOU request.
        new_keys: Keys,
    },
    /// We have established session keys and have now requested an ENR to be fully established.
    AwaitingENR(Keys) 
}

impl EstablishingSession {

    /* Session Generation Functions */

    /// Creates a new `Session` instance and generates a RANDOM packet to be sent along with this
    /// session being established. This session is set to `RandomSent` state.
    pub(crate) fn new_random(contact: NodeContact, request: Request) -> Self {

        let session = EstablishingSession {
            state: SessionState::RandomSent(contact),
            pending_requests: vec![request],
            last_seen_socket: "0.0.0.0:0".parse::<SocketAddr>().expect("Valid Socket"),
        };

        (session, random_packet)
    }

    /// Creates a new `Session` and generates an associated WHOAREYOU packet. The returned session is in the
    /// `WhoAreYouSent` state.
    pub(crate) fn new_whoareyou(
        node_contact: Option<NodeContact>,
    ) -> Self {
        Session {
            state: SessionState::WhoAreYouSent,
            pending_requests: vec![],
            last_seen_socket: "0.0.0.0:0".parse::<SocketAddr>().expect("Valid Socket"),
        }
    }

    /* Update Session State Functions */

    /// Updates a `Random` session state to `WhoAreYouSent`.
    pub(crate) fn whoareyou_sent(&mut self) { 
        self.state = match self.state {
            SessionState::Random(contact) => SessionState::WhoAreYouSent(Some(contact)),
            _ => {
                crit!("Only a Random Session can be upgraded to a WHOAREYOU session")
                return;
            }
        };
    }

    /// Generates session keys from an authentication header. If the IP of the ENR does not match the
    /// source IP address, we consider this session untrusted. The output returns a boolean which
    /// specifies if the Session is trusted or not.
    pub(crate) fn establish_from_header(
        local_key: &CombinedKey,
        local_id: &NodeId,
        remote_id: &NodeId,
        challenge: &Challenge,
        auth_header: &AuthHeader,
    ) -> Result<bool, Discv5Error> {
        // generate session keys
        let (decryption_key, encryption_key, auth_resp_key) = crypto::derive_keys_from_pubkey(
            local_key,
            local_id,
            remote_id,
            &challenge.nonce,
            &auth_header.ephemeral_pubkey,
        )?;

        // decrypt the authentication header
        let auth_response = crypto::decrypt_authentication_header(&auth_resp_key, auth_header)?;

        // check and verify a potential ENR update
        let session_enr = 
            match (auth_response.node_record, challenge.remote_enr) { 
                (Some(new_enr), Some(known_enr) => {
                    if new_enr.seq() > known_enr.seq() {
                        new_enr
                    else {
                        known_enr
                    }
                }
                }
                (Some(new_enr), None) => new_enr
                (None, Some(known_enr) => known_enr
                (None, None) => {
                    warn!("Peer did not respond with their ENR. Session could not be established. Node: {}",remote_id);
                    return Err(Discv5Error::SessionNotEstablished);
                }
        };

        // ENR must exist here
        let remote_public_key = session_enr.public_key();

        // verify the auth header nonce
        if !crypto::verify_authentication_nonce(
            &remote_public_key,
            &auth_header.ephemeral_pubkey,
            &challenge.nonce,
            &auth_response.signature,
        ) {
            return Err(Discv5Error::InvalidSignature);
        }

        let keys = Keys {
            auth_resp_key,
            encryption_key,
            decryption_key,
        };

        Session::new(keys);
    }

    /* Encryption Related Functions */

    /// Encrypts a message and produces an AuthMessage.
    pub(crate) fn encrypt_with_header(
        &mut self,
        tag: Tag,
        local_key: &CombinedKey,
        updated_enr: Option<Enr<CombinedKey>>,
        local_node_id: &NodeId,
        id_nonce: &Nonce,
        message: &[u8],
    ) -> Result<Packet, Discv5Error> {
        


        // generate the session keys
        let (encryption_key, decryption_key, auth_resp_key, ephem_pubkey) =
            crypto::generate_session_keys(
                local_node_id,
                self.remote_enr
                    .as_ref()
                    .expect("Should never be None at this point"),
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
            crypto::encrypt_message(&encryption_key, auth_tag, message, &tag[..])?;

        // update the session state
        match std::mem::replace(&mut self.state, SessionState::Poisoned) {
            SessionState::Established(current_keys) => {
                self.state = SessionState::EstablishedAwaitingResponse {
                    current_keys,
                    new_keys: keys,
                }
            }
            SessionState::Poisoned => unreachable!("Coding error if this is possible"),
            _ => self.state = SessionState::AwaitingResponse(keys),
        }

        Ok(Packet::AuthMessage {
            tag,
            auth_header,
            message: message_ciphertext,
        })
    }

    /// Uses the current `Session` to encrypt a message. Encrypt packets with the current session
    /// key if we are awaiting a response from AuthMessage.
    pub(crate) fn encrypt_message(&self, tag: Tag, message: &[u8]) -> Result<Packet, Discv5Error> {
        //TODO: Establish a counter to prevent repeats of nonce
        let auth_tag: AuthTag = rand::random();

        let cipher = match &self.state {
            SessionState::Established(keys) => {
                crypto::encrypt_message(&keys.encryption_key, auth_tag, message, &tag)?
            }
            SessionState::EstablishedAwaitingResponse { current_keys, .. } => {
                crypto::encrypt_message(&current_keys.encryption_key, auth_tag, message, &tag)?
            }
            _ => return Err(Discv5Error::SessionNotEstablished),
        };

        Ok(Packet::Message {
            tag,
            auth_tag,
            message: cipher,
        })
    }

    /* Decryption Related Functions */

    /// Decrypts an encrypted message. If a Session is already established, the original decryption
    /// keys are tried first, upon failure, the new keys are attempted. If the new keys succeed,
    /// the session keys are updated along with the Session state.
    pub(crate) fn decrypt_message(
        &mut self,
        nonce: AuthTag,
        message: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Discv5Error> {
        let node_id = self.remote_enr.as_ref().expect("ENR must exist").node_id();
        match std::mem::replace(&mut self.state, SessionState::Poisoned) {
            SessionState::Established(keys) => {
                let result = crypto::decrypt_message(&keys.decryption_key, nonce, message, aad);
                self.state = SessionState::Established(keys);
                result
            }
            SessionState::EstablishedAwaitingResponse {
                current_keys,
                new_keys,
            } => {
                // try the original keys first
                match crypto::decrypt_message(&current_keys.decryption_key, nonce, message, aad) {
                    Ok(message) => {
                        // The request for a new session is invalid, throw it away
                        self.state = SessionState::Established(current_keys);
                        Ok(message)
                    }
                    Err(_) => {
                        debug!("Old session key failed to decrypt message");
                        // try decrypt with the new keys

                        match crypto::decrypt_message(&new_keys.decryption_key, nonce, message, aad)
                        {
                            Ok(msg) => {
                                debug!("Session keys have been updated for node: {}", node_id);
                                self.state = SessionState::Established(new_keys);
                                Ok(msg)
                            }
                            Err(e) => {
                                // no set of keys could decrypt the message, maintain the same state
                                self.state = SessionState::EstablishedAwaitingResponse {
                                    current_keys,
                                    new_keys,
                                };
                                Err(e)
                            }
                        }
                    }
                }
            }
            SessionState::AwaitingResponse(keys) => {
                match crypto::decrypt_message(&keys.decryption_key, nonce, message, aad) {
                    Ok(message) => {
                        self.state = SessionState::Established(keys);
                        Ok(message)
                    }
                    Err(e) => {
                        self.state = SessionState::AwaitingResponse(keys);
                        Err(e)
                    }
                }
            }
            SessionState::Poisoned => unreachable!(),
            message_sent_state => {
                // have sent a WHOAREYOU or a RandomPacket, session isn't established
                self.state = message_sent_state;
                Err(Discv5Error::SessionNotEstablished)
            }
        }
    }

    /* Session Helper Functions */

    pub(crate) fn update_enr(&mut self, enr: Enr<CombinedKey>) -> bool {
        if let Some(remote_enr) = &self.remote_enr {
            if remote_enr.seq() < enr.seq() {
                self.remote_enr = Some(enr);
                // ENR has been updated. Check if the state can be promoted to trusted
                return self.update_trusted();
            }
        }
        false
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
