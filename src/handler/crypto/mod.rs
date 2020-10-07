//! Implementation for generating session keys in the Discv5 protocol.
//! Currently, Diffie-Hellman key agreement is performed with known public key types. Session keys
//! are then derived using the HKDF (SHA2-256) key derivation function.
//!
//! There is no abstraction in this module as the specification explicitly defines a singular
//! encryption and key-derivation algorithms. Future versions may abstract some of these to allow
//! for different algorithms.
use crate::error::Discv5Error;
use crate::node_info::NodeContact;
use crate::packet::{IdNonce, MessageNonce};
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm::Aes128Gcm;
use ecdh_ident::EcdhIdent;
use enr::{CombinedKey, CombinedPublicKey, NodeId};
use hkdf::Hkdf;
use secp256k1::Signature;
use sha2::{Digest, Sha256};

mod ecdh_ident;

const NODE_ID_LENGTH: usize = 32;
const INFO_LENGTH: usize = 26 + 2 * NODE_ID_LENGTH;
const KEY_LENGTH: usize = 16;
const KEY_AGREEMENT_STRING: &str = "discovery v5 key agreement";
const NONCE_PREFIX: &str = "discovery-id-nonce";

type Key = [u8; KEY_LENGTH];

/* Session key generation */

/// Generates session and auth-response keys for a nonce and remote ENR. This currently only
/// supports Secp256k1 signed ENR's. This returns four keys; initiator key, responder key, auth
/// response key and the ephemeral public key.
pub(crate) fn generate_session_keys(
    local_id: &NodeId,
    contact: &NodeContact,
    id_nonce: &IdNonce,
) -> Result<(Key, Key, Vec<u8>), Discv5Error> {
    let (secret, ephem_pk) = {
        match contact.public_key() {
            CombinedPublicKey::Secp256k1(remote_pk) => {
                let mut rng = rand::thread_rng();
                let ephem_sk = secp256k1::SecretKey::random(&mut rng);
                let ephem_pk = secp256k1::PublicKey::from_secret_key(&ephem_sk);
                let secret = secp256k1::SharedSecret::<EcdhIdent>::new(&remote_pk, &ephem_sk)
                    .map_err(|_| Discv5Error::KeyDerivationFailed)?;
                // store as uncompressed, strip the first byte and send only 64 bytes.
                let ephem_pk = ephem_pk.serialize()[1..].to_vec();
                (secret, ephem_pk)
            }
            CombinedPublicKey::Ed25519(_) => {
                return Err(Discv5Error::KeyTypeNotSupported("Ed25519"))
            }
        }
    };

    let (initiator_key, recipient_key) =
        derive_key(secret.as_ref(), local_id, &contact.node_id(), id_nonce)?;

    Ok((initiator_key, recipient_key, ephem_pk))
}

fn derive_key(
    secret: &[u8],
    first_id: &NodeId,
    second_id: &NodeId,
    id_nonce: &IdNonce,
) -> Result<(Key, Key), Discv5Error> {
    let mut info = [0u8; INFO_LENGTH];
    info[0..26].copy_from_slice(KEY_AGREEMENT_STRING.as_bytes());
    info[26..26 + NODE_ID_LENGTH].copy_from_slice(&first_id.raw());
    info[26 + NODE_ID_LENGTH..].copy_from_slice(&second_id.raw());

    let hk = Hkdf::<Sha256>::new(Some(id_nonce), secret);

    let mut okm = [0u8; 2 * KEY_LENGTH];
    hk.expand(&info, &mut okm)
        .map_err(|_| Discv5Error::KeyDerivationFailed)?;

    let mut initiator_key: Key = Default::default();
    let mut recipient_key: Key = Default::default();
    initiator_key.copy_from_slice(&okm[0..KEY_LENGTH]);
    recipient_key.copy_from_slice(&okm[KEY_LENGTH..2 * KEY_LENGTH]);

    Ok((initiator_key, recipient_key))
}

/// Derives the session keys for a public key type that matches the local keypair.
pub(crate) fn derive_keys_from_pubkey(
    local_key: &CombinedKey,
    local_id: &NodeId,
    remote_id: &NodeId,
    id_nonce: &IdNonce,
    ephem_pubkey: &[u8],
) -> Result<(Key, Key), Discv5Error> {
    let secret = {
        match local_key {
            CombinedKey::Secp256k1(key) => {
                // convert remote pubkey into secp256k1 public key
                // the key type should match our own node record
                let remote_pubkey = secp256k1::PublicKey::parse_slice(ephem_pubkey, None)
                    .map_err(|_| Discv5Error::InvalidRemotePublicKey)?;

                let secret = secp256k1::SharedSecret::<EcdhIdent>::new(&remote_pubkey, key)
                    .map_err(|_| Discv5Error::KeyDerivationFailed)?;
                secret.as_ref().to_vec()
            }
            CombinedKey::Ed25519(_) => return Err(Discv5Error::KeyTypeNotSupported("Ed25519")),
        }
    };

    derive_key(&secret, remote_id, local_id, id_nonce)
}

/* Nonce Signing */

/// Generates a signature of a nonce given a keypair. This prefixes the `NONCE_PREFIX` to the
/// signature.
pub(crate) fn sign_nonce(
    signing_key: &CombinedKey,
    challenge_data: &[u8],
    ephem_pubkey: &[u8],
    dst_id: &NodeId,
) -> Result<Vec<u8>, Discv5Error> {
    let signing_nonce = generate_signing_nonce(challenge_data, ephem_pubkey, dst_id);

    match signing_key {
        CombinedKey::Secp256k1(key) => {
            let m = secp256k1::Message::parse_slice(&signing_nonce)
                .map_err(|_| Discv5Error::Custom("Could not parse nonce for signing"))?;

            Ok(secp256k1::sign(&m, key).0.serialize().to_vec())
        }
        CombinedKey::Ed25519(_) => Err(Discv5Error::KeyTypeNotSupported("Ed25519")),
    }
}

/// Verifies the authentication header nonce.
pub(crate) fn verify_authentication_nonce(
    remote_pubkey: &CombinedPublicKey,
    remote_ephem_pubkey: &[u8],
    challenge_data: &[u8],
    dst_id: &NodeId,
    sig: &[u8],
) -> bool {
    let signing_nonce = generate_signing_nonce(challenge_data, remote_ephem_pubkey, dst_id);

    match remote_pubkey {
        CombinedPublicKey::Secp256k1(key) => Signature::parse_slice(sig)
            .and_then(|s| {
                secp256k1::Message::parse_slice(&signing_nonce)
                    .map(|m| secp256k1::verify(&m, &s, key))
            })
            .unwrap_or(false),
        CombinedPublicKey::Ed25519(_) => {
            // key not yet supported
            false
        }
    }
}

/// Builds the signature for a given challenge data.
///
/// This takes the SHA256 hash of the nonce.
fn generate_signing_nonce(challenge_data: &[u8], ephem_pubkey: &[u8], dst_id: &NodeId) -> Vec<u8> {
    let mut data = NONCE_PREFIX.as_bytes().to_vec();
    data.extend_from_slice(challenge_data);
    data.extend_from_slice(ephem_pubkey);
    data.extend_from_slice(&dst_id.raw().to_vec());
    Sha256::digest(&data).to_vec()
}

/* Decryption related functions */

/// Decrypt messages that are post-fixed with an authenticated MAC.
pub(crate) fn decrypt_message(
    key: &Key,
    message_nonce: MessageNonce,
    msg: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Discv5Error> {
    if msg.len() < 16 {
        return Err(Discv5Error::DecryptionFailed(
            "Message not long enough to contain a MAC".into(),
        ));
    }

    let aead = Aes128Gcm::new(GenericArray::from_slice(key));
    let payload = Payload { msg, aad };
    aead.decrypt(GenericArray::from_slice(&message_nonce), payload)
        .map_err(|e| Discv5Error::DecryptionFailed(e.to_string()))
}

/* Encryption related functions */

/// A wrapper around the underlying default AES_GCM implementation. This may be abstracted in the
/// future.
pub(crate) fn encrypt_message(
    key: &Key,
    message_nonce: MessageNonce,
    msg: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Discv5Error> {
    let aead = Aes128Gcm::new(GenericArray::from_slice(key));
    let payload = Payload { msg, aad };
    aead.encrypt(GenericArray::from_slice(&message_nonce), payload)
        .map_err(|e| Discv5Error::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::ID_NONCE_LENGTH;
    use enr::{CombinedKey, EnrBuilder, EnrKey};
    use rand;

    fn hex_decode(x: &'static str) -> Vec<u8> {
        hex::decode(x).unwrap()
    }

    fn node_key_1() -> CombinedKey {
        CombinedKey::secp256k1_from_bytes(&mut hex_decode(
            "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f",
        ))
        .unwrap()
    }
    /* This section provides a series of reference tests for the encoding of packets */

    #[test]
    fn ref_test_ecdh() {
        let remote_pubkey = hex::decode("9961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231503061ac4aaee666073d7e5bc2c80c3f5c5b500c1cb5fd0a76abbb6b675ad157").unwrap();
        let local_secret_key =
            hex::decode("fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
                .unwrap();

        let expected_secret =
            hex::decode("033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e")
                .unwrap();

        let mut remote_pk_bytes = [0; 65];
        remote_pk_bytes[0] = 4; // pre-fixes a magic byte indicating this is in uncompressed form
        remote_pk_bytes[1..].copy_from_slice(&remote_pubkey);
        let mut local_sk_bytes = [0; 32];
        local_sk_bytes.copy_from_slice(&local_secret_key);

        let remote_pk = secp256k1::PublicKey::parse(&remote_pk_bytes).unwrap();
        let local_sk = secp256k1::SecretKey::parse(&local_sk_bytes).unwrap();

        let secret = secp256k1::SharedSecret::<EcdhIdent>::new(&remote_pk, &local_sk).unwrap();

        assert_eq!(secret.as_ref(), expected_secret.as_slice());
    }

    #[test]
    fn ref_key_derivation() {
        let secret =
            hex::decode("02a77e3aa0c144ae7c0a3af73692b7d6e5b7a2fdc0eda16e8d5e6cb0d08e88dd04")
                .unwrap();
        let first_node_id = NodeId::parse(
            &hex::decode("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7")
                .unwrap(),
        )
        .unwrap();
        let second_node_id = NodeId::parse(
            &hex::decode("885bba8dfeddd49855459df852ad5b63d13a3fae593f3f9fa7e317fd43651409")
                .unwrap(),
        )
        .unwrap();
        let id_nonce = [1; ID_NONCE_LENGTH];

        let expected_first_key = hex::decode("238d8b50e4363cf603a48c6cc3542967").unwrap();
        let expected_second_key = hex::decode("bebc0183484f7e7ca2ac32e3d72c8891").unwrap();

        let (first_key, second_key) =
            derive_key(&secret, &first_node_id, &second_node_id, &id_nonce).unwrap();

        assert_eq!(first_key.to_vec(), expected_first_key);
        assert_eq!(second_key.to_vec(), expected_second_key);
    }

    #[test]
    fn ref_nonce_signing() {
        let nonce_bytes =
            hex::decode("a77e3aa0c144ae7c0a3af73692b7d6e5b7a2fdc0eda16e8d5e6cb0d08e88dd04")
                .unwrap();
        let ephemeral_pubkey =
            hex::decode("0x039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231")
                .unwrap();
        let local_secret_key =
            hex::decode("0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
                .unwrap();
        let dst_id: NodeId = node_key_1().public().into();

        let expected_sig = hex::decode("0x94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6").unwrap();

        let challenge_data = hex::decode("0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000").unwrap();

        nonce.copy_from_slice(&nonce_bytes);
        let key = secp256k1::SecretKey::parse_slice(&local_secret_key).unwrap();
        let sig = sign_nonce(&key.into(), &nonce, &ephemeral_pubkey, &dst_id).unwrap();

        assert_eq!(sig, expected_sig);
    }

    #[test]
    fn ref_encryption() {
        let key_bytes = hex::decode("9f2d77db7004bf8a1a85107ac686990b").unwrap();
        let nonce_bytes = hex::decode("27b5af763c446acd2749fe8e").unwrap();
        let pt = hex::decode("01c20101").unwrap();
        let ad = hex::decode("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
            .unwrap();
        let expected_ciphertext = hex::decode("a5d12a2d94b8ccb3ba55558229867dc13bfa3648").unwrap();

        let mut key = [0u8; 16];
        key.copy_from_slice(&key_bytes);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext = encrypt_message(&key, nonce, &pt, &ad).unwrap();

        assert_eq!(ciphertext, expected_ciphertext);
    }

    /* This section provides functionality testing */

    #[test]
    fn derive_symmetric_keys() {
        let node1_key = CombinedKey::generate_secp256k1();
        let node2_key = CombinedKey::generate_secp256k1();

        let node1_enr = EnrBuilder::new("v4").build(&node1_key).unwrap();
        let node2_enr = EnrBuilder::new("v4").build(&node2_key).unwrap();

        let id_nonce: IdNonce = rand::random();

        let (key1, key2, pk) =
            generate_session_keys(&node1_enr.node_id(), &node2_enr.clone().into(), &id_nonce)
                .unwrap();
        let (key4, key5) = derive_keys_from_pubkey(
            &node2_key,
            &node2_enr.node_id(),
            &node1_enr.node_id(),
            &id_nonce,
            &pk,
        )
        .unwrap();

        assert_eq!(key1, key4);
        assert_eq!(key2, key5);
    }

    #[test]
    fn encrypt_decrypt() {
        // aad
        let aad: [u8; 12] = rand::random();
        let msg: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let key: Key = rand::random();
        let nonce: MessageNonce = rand::random();

        let cipher = encrypt_message(&key, nonce, &msg, &aad).unwrap();
        let plain_text = decrypt_message(&key, nonce, &cipher, &aad).unwrap();

        assert_eq!(plain_text, msg);
    }
}
