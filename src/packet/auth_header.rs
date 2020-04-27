///! The Authentication header associated with Discv5 Packets.
use super::{AuthTag, Nonce, AUTH_TAG_LENGTH, ID_NONCE_LENGTH};
use enr::{CombinedKey, Enr};
use log::debug;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

//TODO: Generalise the scheme and associated crypto library.
const AUTH_SCHEME_NAME: &str = "gcm";
const AUTH_RESPONSE_VERSION: u8 = 5;

/// The Authentication header.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthHeader {
    /// Authentication nonce.
    pub auth_tag: AuthTag,

    /// The nonce of the associated WHOAREYOU packet.
    pub id_nonce: Nonce,

    /// The authentication scheme.
    pub auth_scheme_name: &'static str,

    /// The public key as a raw encoded bytes.
    pub ephemeral_pubkey: Vec<u8>,

    /// Authentication response.
    pub auth_response: Vec<u8>,
}

impl AuthHeader {
    pub fn new(
        auth_tag: AuthTag,
        id_nonce: Nonce,
        ephemeral_pubkey: Vec<u8>,
        resp: Vec<u8>,
    ) -> Self {
        AuthHeader {
            auth_tag,
            id_nonce,
            auth_scheme_name: AUTH_SCHEME_NAME,
            ephemeral_pubkey,
            auth_response: resp,
        }
    }
}

/// An authentication response. This contains a signed challenge nonce, and optionally an updated
/// ENR if the requester has an outdated ENR.
pub struct AuthResponse {
    /// The current version of the protocol. Currently set to 5.
    pub version: u8,

    /// A signature of the challenge nonce.
    pub signature: Vec<u8>,

    /// An optional ENR, required if the requester has an out-dated ENR.
    pub node_record: Option<Enr<CombinedKey>>,
}

impl AuthResponse {
    pub fn new(sig: &[u8], node_record: Option<Enr<CombinedKey>>) -> Self {
        AuthResponse {
            version: AUTH_RESPONSE_VERSION,
            signature: sig.to_vec(),
            node_record,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut s = RlpStream::new();
        s.append(self);
        s.drain()
    }
}

impl Encodable for AuthResponse {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.version);
        s.append(&self.signature.to_vec());
        // requires custom encoding. None is encoded as rlp []
        if let Some(node_record) = &self.node_record {
            s.append(node_record);
        } else {
            s.begin_list(0);
        }
    }
}

impl Decodable for AuthResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() {
            return Err(DecoderError::RlpExpectedToBeList);
        }

        let version = rlp.val_at::<u8>(0)?;
        let signature = rlp.val_at::<Vec<u8>>(1)?;
        let node_record_rlp = rlp.at(2)?;
        let node_record = {
            if node_record_rlp.is_empty() {
                None
            } else {
                Some(node_record_rlp.as_val::<Enr<CombinedKey>>()?)
            }
        };

        Ok(AuthResponse {
            version,
            signature,
            node_record,
        })
    }
}

impl Encodable for AuthHeader {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5);
        s.append(&self.auth_tag.to_vec());
        s.append(&self.id_nonce.to_vec());
        s.append(&self.auth_scheme_name);
        s.append(&self.ephemeral_pubkey.clone());
        s.append(&self.auth_response.to_vec());
    }
}

impl Decodable for AuthHeader {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.item_count() {
            Ok(size) => {
                if size != 5 {
                    if size == 3 {
                        // This is likely due to using the wrong ENR
                        debug!("Decoding failed. We likely sent an invalid node id");
                    } else {
                        debug!("Failed to decode Authentication header. Incorrect list size. Length: {}, expected 5", size);
                    }
                    return Err(DecoderError::RlpIncorrectListLen);
                }
            }
            Err(e) => {
                debug!(
                    "Failed to decode Authentication header. Not an RLP list. Error: {}",
                    e
                );
            }
        }

        let mut decoded_list = match rlp.as_list::<Vec<u8>>() {
            Ok(v) => v,
            Err(_) => {
                debug!("Could not decode Authentication header: {}", rlp);
                return Err(DecoderError::Custom("List decode fail"));
            }
        };

        let auth_response = decoded_list
            .pop()
            .ok_or_else(|| DecoderError::RlpExpectedToBeData)?;
        let pubkey_bytes = decoded_list
            .pop()
            .ok_or_else(|| DecoderError::RlpExpectedToBeData)?;
        let auth_scheme_bytes = decoded_list
            .pop()
            .ok_or_else(|| DecoderError::RlpExpectedToBeData)?;
        let id_nonce_bytes = decoded_list
            .pop()
            .ok_or_else(|| DecoderError::RlpExpectedToBeData)?;
        let auth_tag_bytes = decoded_list
            .pop()
            .ok_or_else(|| DecoderError::RlpExpectedToBeData)?;

        let mut auth_tag: AuthTag = Default::default();
        if auth_tag_bytes.len() > AUTH_TAG_LENGTH {
            return Err(DecoderError::Custom("Invalid Authtag length"));
        }
        auth_tag[AUTH_TAG_LENGTH - auth_tag_bytes.len()..].copy_from_slice(&auth_tag_bytes);

        let mut id_nonce: Nonce = Default::default();
        if id_nonce_bytes.len() > ID_NONCE_LENGTH {
            return Err(DecoderError::Custom("Invalid Nonce length"));
        }
        id_nonce[ID_NONCE_LENGTH - id_nonce_bytes.len()..].copy_from_slice(&id_nonce_bytes);

        // currently only support gcm scheme
        let auth_scheme_name = String::from_utf8_lossy(&auth_scheme_bytes);
        if auth_scheme_name != AUTH_SCHEME_NAME {
            debug!(
                "Failed to decode Authentication header. Unknown auth scheme: {}",
                auth_scheme_name
            );
            return Err(DecoderError::Custom("Invalid Authentication Scheme"));
        }

        // Do not decode into libp2p public keys, this is done upstream
        let ephemeral_pubkey = pubkey_bytes.clone();

        Ok(AuthHeader {
            auth_tag,
            id_nonce,
            auth_scheme_name: AUTH_SCHEME_NAME,
            ephemeral_pubkey,
            auth_response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::EnrBuilder;
    use rand;

    #[test]
    fn encode_decode_auth_response() {
        let sig: [u8; 32] = rand::random();

        let key = CombinedKey::generate_secp256k1();
        let tcp = 30303;

        let enr = {
            let mut builder = EnrBuilder::new("v4");
            builder.tcp(tcp);
            builder.build(&key).unwrap()
        };

        let auth_response = AuthResponse::new(&sig, Some(enr.clone()));

        let encoded_auth_response = auth_response.encode();

        let decoded_auth_response = rlp::decode::<AuthResponse>(&encoded_auth_response).unwrap();

        assert_eq!(decoded_auth_response.signature, sig);
        assert_eq!(decoded_auth_response.node_record, Some(enr));
    }

    #[test]
    fn encode_decode_auth_response_no_enr() {
        let sig: [u8; 32] = rand::random();

        let auth_response = AuthResponse::new(&sig, None);

        let encoded_auth_response = auth_response.encode();

        let decoded_auth_response = rlp::decode::<AuthResponse>(&encoded_auth_response).unwrap();

        assert_eq!(decoded_auth_response.signature, sig);
    }
}
