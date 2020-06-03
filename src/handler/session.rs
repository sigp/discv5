use super::node_info::NodeContact;
use super::*;
use crate::packet::AuthResponse;
use enr::{CombinedKey, NodeId};
use zeroize::Zeroize;

#[derive(Zeroize, PartialEq)]
pub(crate) struct Keys {
    /// The Authentication response key.
    auth_resp_key: [u8; 16],

    /// The encryption key.
    encryption_key: [u8; 16],

    /// The decryption key.
    decryption_key: [u8; 16],
}

pub struct Session {
    pub contact: NodeContact,
    keys: Keys,
    awaiting_keys: Option<Keys>,
    pub trusted: bool,
}

impl Session {
    pub fn new(contact: NodeContact, keys: Keys) -> Self {
        Session {
            contact,
            keys,
            awaiting_keys: None,
            trusted: false,
        }
    }
}

impl Session {
    /// Uses the current `Session` to encrypt a message. Encrypt packets with the current session
    /// key if we are awaiting a response from AuthMessage.
    pub(crate) fn encrypt_message(&self, tag: Tag, message: &[u8]) -> Result<Packet, Discv5Error> {
        //TODO: Establish a counter to prevent repeats of nonce
        let auth_tag: AuthTag = rand::random();

        let cipher = crypto::encrypt_message(&self.keys.encryption_key, auth_tag, message, &tag)?;
        Ok(Packet::Message {
            tag,
            auth_tag,
            message: cipher,
        })
    }

    /// Decrypts an encrypted message. If a Session is already established, the original decryption
    /// keys are tried first, upon failure, the new keys are attempted. If the new keys succeed,
    /// the session keys are updated along with the Session state.
    pub(crate) fn decrypt_message(
        &mut self,
        nonce: AuthTag,
        message: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Discv5Error> {
        let node_id = self.contact.node_id();
        // try with the new keys
        if let Some(new_keys) = self.new_keys.take() {
            let result =
                crypto::decrypt_message(&self.new_keys.decryption_key, nonce, message, aad);
            if result.ok() {
                self.keys = new_keys;
                return result;
            }
        }
        // if it failed try with the old keys
        crypto::decrypt_message(&self.keys.decryption_key, nonce, message, aad)
    }

    /* Session Helper Functions */

    pub(crate) fn update_enr(&mut self, enr: Enr) -> bool {
        self.contact.update_enr(enr);
    }
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
) -> Result<Session, Discv5Error> {
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
    let session_enr = match (auth_response.node_record, challenge.remote_enr) {
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

    let contact = session_enr.into();

    Session::new(contact, keys)
}

/// Encrypts a message and produces an AuthMessage.
pub(crate) fn encrypt_with_header(
    tag: Tag,
    local_key: &CombinedKey,
    updated_enr: Option<Enr>,
    local_node_id: &NodeId,
    remote_enr: Option<Enr>,
    id_nonce: &Nonce,
    message: &[u8],
) -> Result<(Packet, Session), Discv5Error> {
    // generate the session keys
    let (encryption_key, decryption_key, auth_resp_key, ephem_pubkey) =
        crypto::generate_session_keys(
            local_node_id,
            remote_enr
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
    let message_ciphertext = crypto::encrypt_message(&encryption_key, auth_tag, message, &tag[..])?;

    let packet = Packet::AuthMessage {
        tag,
        auth_header,
        message: message_ciphertext,
    };

    let session = Session::new(keys, remote_enr);

    Ok(packet, session);
}
