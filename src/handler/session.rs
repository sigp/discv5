use super::*;
use crate::{
    node_info::NodeContact,
    packet::{ChallengeData, Packet, PacketHeader, PacketKind, MESSAGE_NONCE_LENGTH},
};
use enr::{CombinedKey, NodeId};
use zeroize::Zeroize;

#[derive(Zeroize, PartialEq)]
pub(crate) struct Keys {
    /// The encryption key.
    encryption_key: [u8; 16],
    /// The decryption key.
    decryption_key: [u8; 16],
}

/// A Session containing the encryption/decryption keys. These are kept individually for a given
/// node.
pub(crate) struct Session {
    /// The current keys used to encrypt/decrypt messages.
    keys: Keys,
    /// If a new handshake is being established, these keys can be tried to determine if this new
    /// set of keys is canon.
    awaiting_keys: Option<Keys>,
    /// If we contacted this node without an ENR, i.e. via a multiaddr, during the session
    /// establishment we request the nodes ENR. Once the ENR is received and verified, this session
    /// becomes established.
    ///
    /// This field holds the request_id associated with the ENR request.
    pub awaiting_enr: Option<RequestId>,
    /// Number of messages sent. Used to ensure the nonce used in message encryption is always
    /// unique.
    counter: u32,
}

impl Session {
    pub fn new(keys: Keys) -> Self {
        Session {
            keys,
            awaiting_keys: None,
            awaiting_enr: None,
            counter: 0,
        }
    }

    /// A new session has been established. Update this session based on the new session.
    pub fn update(&mut self, new_session: Session) {
        // Await the new sessions keys
        self.awaiting_keys = Some(new_session.keys);
        self.awaiting_enr = new_session.awaiting_enr;
    }

    /// Uses the current `Session` to encrypt a message. Encrypt packets with the current session
    /// key if we are awaiting a response from AuthMessage.
    pub(crate) fn encrypt_message(
        &mut self,
        src_id: NodeId,
        message: &[u8],
    ) -> Result<Packet, Discv5Error> {
        self.counter += 1;

        // If the message nonce length is ever set below 4 bytes this will explode. The packet
        // size constants shouldn't be modified.
        let random_nonce: [u8; MESSAGE_NONCE_LENGTH - 4] = rand::random();
        let mut message_nonce: MessageNonce = [0u8; crate::packet::MESSAGE_NONCE_LENGTH];
        message_nonce[..4].copy_from_slice(&self.counter.to_be_bytes());
        message_nonce[4..].copy_from_slice(&random_nonce);

        // the authenticated data is the IV concatenated with the packet header
        let iv: u128 = rand::random();
        let header = PacketHeader {
            message_nonce,
            kind: PacketKind::Message { src_id },
        };

        let mut authenticated_data = iv.to_be_bytes().to_vec();
        authenticated_data.extend_from_slice(&header.encode());

        let cipher = crypto::encrypt_message(
            &self.keys.encryption_key,
            message_nonce,
            message,
            &authenticated_data,
        )?;

        // construct a packet from the header and the cipher text
        Ok(Packet {
            iv,
            header,
            message: cipher,
        })
    }

    /// Decrypts an encrypted message. If a Session is already established, the original decryption
    /// keys are tried first, upon failure, the new keys are attempted. If the new keys succeed,
    /// the session keys are updated along with the Session state.
    pub(crate) fn decrypt_message(
        &mut self,
        message_nonce: MessageNonce,
        message: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Discv5Error> {
        // try with the new keys
        if let Some(new_keys) = self.awaiting_keys.take() {
            let result =
                crypto::decrypt_message(&new_keys.decryption_key, message_nonce, message, aad);
            if result.is_ok() {
                self.keys = new_keys;
                return result;
            }
        }
        // if it failed try with the old keys
        crypto::decrypt_message(&self.keys.decryption_key, message_nonce, message, aad)
    }

    /* Session Helper Functions */

    /// Generates session keys from an authentication header. If the IP of the ENR does not match the
    /// source IP address, we consider this session untrusted. The output returns a boolean which
    /// specifies if the Session is trusted or not.
    pub(crate) fn establish_from_challenge(
        local_key: Arc<RwLock<CombinedKey>>,
        local_id: &NodeId,
        remote_id: &NodeId,
        challenge: Challenge,
        id_nonce_sig: &[u8],
        ephem_pubkey: &[u8],
        enr_record: Option<Enr>,
    ) -> Result<(Session, Enr), Discv5Error> {
        // check and verify a potential ENR update

        // Duplicate code here to avoid cloning an ENR
        let remote_public_key = {
            let enr = match (enr_record.as_ref(), challenge.remote_enr.as_ref()) {
                (Some(new_enr), Some(known_enr)) => {
                    if new_enr.seq() > known_enr.seq() {
                        new_enr
                    } else {
                        known_enr
                    }
                }
                (Some(new_enr), None) => new_enr,
                (None, Some(known_enr)) => known_enr,
                (None, None) => {
                    warn!(
                "Peer did not respond with their ENR. Session could not be established. Node: {}",
                remote_id
            );
                    return Err(Discv5Error::SessionNotEstablished);
                }
            };
            enr.public_key()
        };

        // verify the auth header nonce
        if !crypto::verify_authentication_nonce(
            &remote_public_key,
            ephem_pubkey,
            &challenge.data,
            local_id,
            id_nonce_sig,
        ) {
            return Err(Discv5Error::InvalidChallengeSignature(challenge));
        }

        // The keys are derived after the message has been verified to prevent potential extra work
        // for invalid messages.

        // generate session keys
        let (decryption_key, encryption_key) = crypto::derive_keys_from_pubkey(
            &local_key.read(),
            local_id,
            remote_id,
            &challenge.data,
            ephem_pubkey,
        )?;

        let keys = Keys {
            encryption_key,
            decryption_key,
        };

        // Takes ownership of the provided ENRs - Slightly annoying code duplication, but avoids
        // cloning ENRs
        let session_enr = match (enr_record, challenge.remote_enr) {
            (Some(new_enr), Some(known_enr)) => {
                if new_enr.seq() > known_enr.seq() {
                    new_enr
                } else {
                    known_enr
                }
            }
            (Some(new_enr), None) => new_enr,
            (None, Some(known_enr)) => known_enr,
            (None, None) => unreachable!("Checked in the first match above"),
        };

        Ok((Session::new(keys), session_enr))
    }

    /// Encrypts a message and produces an AuthMessage.
    pub(crate) fn encrypt_with_header(
        remote_contact: &NodeContact,
        local_key: Arc<RwLock<CombinedKey>>,
        updated_enr: Option<Enr>,
        local_node_id: &NodeId,
        challenge_data: &ChallengeData,
        message: &[u8],
    ) -> Result<(Packet, Session), Discv5Error> {
        // generate the session keys
        let (encryption_key, decryption_key, ephem_pubkey) =
            crypto::generate_session_keys(local_node_id, remote_contact, challenge_data)?;

        let keys = Keys {
            encryption_key,
            decryption_key,
        };

        // construct the nonce signature
        let sig = crypto::sign_nonce(
            &local_key.read(),
            challenge_data,
            &ephem_pubkey,
            &remote_contact.node_id(),
        )
        .map_err(|_| Discv5Error::Custom("Could not sign WHOAREYOU nonce"))?;

        // build an authentication packet
        let message_nonce: MessageNonce = rand::random();
        let mut packet = Packet::new_authheader(
            *local_node_id,
            message_nonce,
            sig,
            ephem_pubkey,
            updated_enr,
        );

        // Create the authenticated data for the new packet.

        let mut authenticated_data = packet.iv.to_be_bytes().to_vec();
        authenticated_data.extend_from_slice(&packet.header.encode());

        // encrypt the message
        let message_ciphertext =
            crypto::encrypt_message(&encryption_key, message_nonce, message, &authenticated_data)?;

        packet.message = message_ciphertext;

        let session = Session::new(keys);

        Ok((packet, session))
    }
}
