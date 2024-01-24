use super::*;
use crate::{
    handler::Challenge,
    node_info::NodeContact,
    packet::{
        ChallengeData, MessageNonce, Packet, PacketHeader, PacketKind, ProtocolIdentity,
        MESSAGE_NONCE_LENGTH,
    },
    rpc::RequestId,
    Discv5Error, Enr,
};

use enr::{CombinedKey, NodeId};
use parking_lot::RwLock;
use std::sync::Arc;
use zeroize::Zeroize;

#[derive(Zeroize, PartialEq)]
pub(crate) struct Keys {
    /// The encryption key.
    encryption_key: [u8; 16],
    /// The decryption key.
    decryption_key: [u8; 16],
}

impl From<([u8; 16], [u8; 16])> for Keys {
    fn from((encryption_key, decryption_key): ([u8; 16], [u8; 16])) -> Self {
        Keys {
            encryption_key,
            decryption_key,
        }
    }
}

/// A Session containing the encryption/decryption keys. These are kept individually for a given
/// node.
pub(crate) struct Session {
    /// The current keys used to encrypt/decrypt messages.
    keys: Keys,
    /// If a new handshake is being established, the older keys are maintained as race
    /// conditions in the handshake can give different views of which keys are canon.
    /// The key that worked to decrypt our last message (or are freshly established) exist in
    /// `keys` and previous keys are optionally stored in `old_keys`. We attempt to decrypt
    /// messages with `keys` before optionally trying `old_keys`.
    old_keys: Option<Keys>,
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
            old_keys: None,
            awaiting_enr: None,
            counter: 0,
        }
    }

    /// A new session has been established. Update this session based on the new session.
    pub fn update(&mut self, new_session: Session) {
        // Optimistically assume the new keys are canonical.
        self.old_keys = Some(std::mem::replace(&mut self.keys, new_session.keys));
        self.awaiting_enr = new_session.awaiting_enr;
    }

    /// Uses the current `Session` to encrypt a `SessionMessage`.
    pub(crate) fn encrypt_session_message<P: ProtocolIdentity>(
        &mut self,
        src_id: NodeId,
        message: &[u8],
    ) -> Result<Packet, Discv5Error> {
        self.encrypt::<P>(message, PacketKind::SessionMessage { src_id })
    }

    /// Uses the current `Session` to encrypt a `Message`.
    pub(crate) fn encrypt_message<P: ProtocolIdentity>(
        &mut self,
        src_id: NodeId,
        message: &[u8],
    ) -> Result<Packet, Discv5Error> {
        self.encrypt::<P>(message, PacketKind::Message { src_id })
    }

    /// Encrypts packets with the current session key if we are awaiting a response from
    /// AuthMessage.
    fn encrypt<P: ProtocolIdentity>(
        &mut self,
        message: &[u8],
        packet_kind: PacketKind,
    ) -> Result<Packet, Discv5Error> {
        self.counter += 1;

        let random_nonce: [u8; MESSAGE_NONCE_LENGTH - 4] = rand::random();
        let mut message_nonce: MessageNonce = [0u8; MESSAGE_NONCE_LENGTH];
        message_nonce[..4].copy_from_slice(&self.counter.to_be_bytes());
        message_nonce[4..].copy_from_slice(&random_nonce);

        // the authenticated data is the IV concatenated with the packet header
        let iv: u128 = rand::random();
        let header = PacketHeader {
            message_nonce,
            kind: packet_kind,
        };

        let mut authenticated_data = iv.to_be_bytes().to_vec();
        authenticated_data.extend_from_slice(&header.encode::<P>());

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
        // First try with the canonical keys.
        let result_canon =
            crypto::decrypt_message(&self.keys.decryption_key, message_nonce, message, aad);

        // If decryption is fine, nothing more to do.
        if result_canon.is_ok() {
            return result_canon;
        }

        // If these keys did not work, try old_keys
        if let Some(old_keys) = self.old_keys.take() {
            let result =
                crypto::decrypt_message(&old_keys.decryption_key, message_nonce, message, aad);
            if result.is_ok() {
                // rotate the keys
                self.old_keys = Some(std::mem::replace(&mut self.keys, old_keys));
            }
            return result;
        }
        result_canon
    }

    /* Session Helper Functions */

    /// Generates session keys from an authentication header. If the IP of the ENR does not match the
    /// source IP address, we consider this session untrusted. The output returns a boolean which
    /// specifies if the Session is trusted or not.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn establish_from_challenge(
        local_key: Arc<RwLock<CombinedKey>>,
        local_id: &NodeId,
        remote_id: &NodeId,
        challenge_data: ChallengeData,
        id_nonce_sig: &[u8],
        ephem_pubkey: &[u8],
        session_enr: Enr,
    ) -> Result<(Session, Enr), Discv5Error> {
        // verify the auth header nonce
        if !crypto::verify_authentication_nonce(
            &session_enr.public_key(),
            ephem_pubkey,
            &challenge_data,
            local_id,
            id_nonce_sig,
        ) {
            let challenge = Challenge {
                data: challenge_data,
                remote_enr: Some(session_enr),
            };
            return Err(Discv5Error::InvalidChallengeSignature(challenge));
        }

        // The keys are derived after the message has been verified to prevent potential extra work
        // for invalid messages.

        // generate session keys
        let (decryption_key, encryption_key) = crypto::derive_keys_from_pubkey(
            &local_key.read(),
            local_id,
            remote_id,
            &challenge_data,
            ephem_pubkey,
        )?;

        let keys = Keys {
            encryption_key,
            decryption_key,
        };

        Ok((Session::new(keys), session_enr))
    }

    /// Encrypts a message and produces an AuthMessage.
    pub(crate) fn encrypt_with_header<P: ProtocolIdentity>(
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
        authenticated_data.extend_from_slice(&packet.header.encode::<P>());

        // encrypt the message
        let message_ciphertext =
            crypto::encrypt_message(&encryption_key, message_nonce, message, &authenticated_data)?;

        packet.message = message_ciphertext;

        let session = Session::new(keys);

        Ok((packet, session))
    }
}

#[cfg(test)]
pub(crate) fn build_dummy_session() -> Session {
    Session::new(Keys {
        encryption_key: [0; 16],
        decryption_key: [0; 16],
    })
}
