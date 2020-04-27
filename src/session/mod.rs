//! The `Session` struct handles the stages of creating and establishing a handshake with a
//! peer.
//!
//! There are two ways a Session can get initialised.
//!
//! - An RPC request to an unknown peer is requested by the application. In this scenario, a RANDOM packet is sent to the unknown peer. This session is created using the `new_random()` function.
//! - A message was received from an unknown peer and we start the `Session` by sending a
//! WHOAREYOU message.
//!
//! This `Session` module is responsible for generating, deriving and holding keys for sessions for known peers.

use super::packet::{AuthHeader, AuthResponse, AuthTag, Nonce, Packet, Tag, MAGIC_LENGTH};
use crate::Discv5Error;
use enr::{CombinedKey, Enr, NodeId};
use log::debug;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use zeroize::Zeroize;

mod crypto;
mod ecdh_ident;

const WHOAREYOU_STRING: &str = "WHOAREYOU";

/// Manages active handshakes and connections between nodes in discv5. There are three main states
/// a session can be in, initializing (`WhoAreYouSent` or `RandomSent`), `Untrusted` (when the
/// socket address of the ENR doesn't match the `last_seen_socket`) and `Established` (the session
/// has been successfully established).
pub struct Session {
    /// The current state of the Session
    state: SessionState,

    /// Whether the last seen socket address of the peer matches its known ENR. If it does not, the
    /// session is considered untrusted, and outgoing messages are not sent.
    trusted: TrustedState,

    /// The ENR of the remote node. This may be unknown during `WhoAreYouSent` states.
    remote_enr: Option<Enr<CombinedKey>>,

    /// Last seen IP address and port. This is used to determine if the session is trusted or not.
    last_seen_socket: SocketAddr,
}

#[derive(Zeroize, PartialEq)]
pub struct Keys {
    /// The Authentication response key.
    pub auth_resp_key: [u8; 16],

    /// The encryption key.
    pub encryption_key: [u8; 16],

    /// The decryption key.
    pub decryption_key: [u8; 16],
}

/// A State
pub enum TrustedState {
    /// The ENR socket address matches what is observed
    Trusted,
    /// The source socket address of the last message doesn't match the known ENR. In this state, the service will respond to requests, but does not treat the node as
    /// connected until the IP is updated to match the source IP.
    Untrusted,
}

#[derive(PartialEq)]
/// The current state of the session. This enum holds the encryption keys for various states.
pub enum SessionState {
    /// A WHOAREYOU packet has been sent, and the Session is awaiting an Authentication response.
    WhoAreYouSent,

    /// A RANDOM packet has been sent and the Session is awaiting a WHOAREYOU response.
    RandomSent,

    /// An AuthMessage has been sent with a new set of generated keys. Once a response has been
    /// received that we can decrypt, the session transitions to an established state, replacing
    /// any current set of keys. No Session is currently active.
    AwaitingResponse(Keys),

    /// An established Session has received a WHOAREYOU. In this state, messages are sent
    /// out with the established sessions keys and new encrypted messages are first attempted to
    /// be decrypted with the established session keys, upon failure, the new keys are tried. If
    /// the new keys are successful, the session keys are updated and the state progresses to
    /// `Established`.
    EstablishedAwaitingResponse {
        /// The keys used in the current established session.
        current_keys: Keys,
        /// New keys generated from a recent WHOARYOU request.
        new_keys: Keys,
    },

    /// A Session has been established and the ENR IP matches the source IP.
    Established(Keys),

    /// Processing has failed. Fatal error.
    Poisoned,
}

impl Session {
    /* Session Generation Functions */

    /// Creates a new `Session` instance and generates a RANDOM packet to be sent along with this
    /// session being established. This session is set to `RandomSent` state.
    pub fn new_random(tag: Tag, remote_enr: Enr<CombinedKey>) -> (Self, Packet) {
        let random_packet = Packet::random(tag);

        let session = Session {
            state: SessionState::RandomSent,
            trusted: TrustedState::Untrusted,
            remote_enr: Some(remote_enr),
            last_seen_socket: "0.0.0.0:0".parse::<SocketAddr>().expect("Valid Socket"),
        };

        (session, random_packet)
    }

    /// Creates a new `Session` and generates an associated WHOAREYOU packet. The returned session is in the
    /// `WhoAreYouSent` state.
    pub fn new_whoareyou(
        node_id: &NodeId,
        enr_seq: u64,
        remote_enr: Option<Enr<CombinedKey>>,
        auth_tag: AuthTag,
    ) -> (Self, Packet) {
        // build the WHOAREYOU packet
        let whoareyou_packet = {
            let magic = {
                let mut hasher = Sha256::new();
                hasher.input(node_id.raw());
                hasher.input(WHOAREYOU_STRING.as_bytes());
                let mut magic = [0u8; MAGIC_LENGTH];
                magic.copy_from_slice(&hasher.result());
                magic
            };

            let id_nonce: Nonce = rand::random();

            Packet::WhoAreYou {
                magic,
                token: auth_tag,
                id_nonce,
                enr_seq,
            }
        };

        let session = Session {
            state: SessionState::WhoAreYouSent,
            trusted: TrustedState::Untrusted,
            remote_enr,
            last_seen_socket: "0.0.0.0:0".parse::<SocketAddr>().expect("Valid Socket"),
        };

        (session, whoareyou_packet)
    }

    /* Update Session State Functions */

    /// Generates session keys from an authentication header. If the IP of the ENR does not match the
    /// source IP address, we consider this session untrusted. The output returns a boolean which
    /// specifies if the Session is trusted or not.
    pub fn establish_from_header(
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
                    self.remote_enr = Some(enr.clone());
                } // ignore ENR's that have a lower seq number
            } else {
                // update the ENR
                self.remote_enr = Some(enr.clone());
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

    /* Encryption Related Functions */

    /// Encrypts a message and produces an AuthMessage.
    pub fn encrypt_with_header(
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
            id_nonce.clone(),
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
    pub fn encrypt_message(&self, tag: Tag, message: &[u8]) -> Result<Packet, Discv5Error> {
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
    pub fn decrypt_message(
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

    pub fn update_enr(&mut self, enr: Enr<CombinedKey>) -> bool {
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
    pub fn update_trusted(&mut self) -> bool {
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
    pub fn set_last_seen_socket(&mut self, socket: SocketAddr) {
        self.last_seen_socket = socket;
    }

    pub fn is_whoareyou_sent(&self) -> bool {
        SessionState::WhoAreYouSent == self.state
    }

    pub fn is_random_sent(&self) -> bool {
        SessionState::RandomSent == self.state
    }

    pub fn is_awaiting_response(&self) -> bool {
        if let SessionState::AwaitingResponse(_) = self.state {
            true
        } else {
            false
        }
    }

    pub fn remote_enr(&self) -> &Option<Enr<CombinedKey>> {
        &self.remote_enr
    }

    pub fn is_trusted(&self) -> bool {
        if let TrustedState::Trusted = self.trusted {
            true
        } else {
            false
        }
    }

    /// Returns true if the Session is trusted and has established session keys. This state means
    /// the session is capable of sending requests.
    pub fn trusted_established(&self) -> bool {
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
