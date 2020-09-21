//! This module defines the raw UDP message packets for Discovery v5.1.
//!
//! The [discv5 wire specification](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) provides further information on UDP message packets as implemented in this module.
//!
//! A [`Packet`] defines all raw UDP message variants and implements the encoding/decoding
//! logic.
//!
//! Note, that all message encryption/decryption is handled outside of this module.
//!
//! [`Packet`]: enum.Packet.html

use crate::error::PacketError;
use crate::Enr;
use enr::NodeId;
use rand::Rng;
use std::convert::TryInto;

use aes_ctr::stream_cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes128Ctr;
use zeroize::Zeroize;

/// The packet IV length (u128).
pub const IV_LENGTH: usize = 16;
/// The length of the static header. (8 byte protocol id, 32 byte src-id, 1 byte flag, 2 byte
/// authdata-size).
pub const STATIC_HEADER_LENGTH: usize = 43;
/// The message nonce length (in bytes).
pub const MESSAGE_NONCE_LENGTH: usize = 12;
/// The Id nonce legnth (in bytes).
pub const ID_NONCE_LENGTH: usize = 32;

/// Protocol ID sent with each message.
const PROTOCOL_ID: &str = "discv5  ";
/// The version sent with each handshake.
const VERSION: u8 = 1;

/// Message Nonce (12 bytes).
pub type MessageNonce = [u8; MESSAGE_NONCE_LENGTH];
/// The nonce sent in a WHOAREYOU packet.
pub type IdNonce = [u8; ID_NONCE_LENGTH];

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    /// Random data unique to the packet.
    pub iv: u128,
    /// Protocol header.
    pub header: PacketHeader,
    /// The message contents itself.
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketHeader {
    /// The source NodeId of the packet.
    pub src_id: NodeId,
    /// The type of packet this is.
    pub flag: PacketType,
}

impl PacketHeader {
    // Encodes the header to bytes to be included into the `masked-header` of the Packet Encoding.
    pub fn encode(&self) -> Vec<u8> {
        let auth_data = self.flag.encode();
        let mut buf = Vec::with_capacity(auth_data.len() + 8 + 32 + 1 + 2); // protocol_id size + node_id size + flag + authdata_size
        buf.extend_from_slice(PROTOCOL_ID.as_bytes());
        buf.extend_from_slice(&self.src_id.raw());
        let flag: u8 = (&self.flag).into();
        buf.extend_from_slice(&flag.to_be_bytes());
        buf.extend_from_slice(&(auth_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&auth_data);

        buf
    }

    // If the packet is not a challenge, the authenticated data is the encoded header.
    pub fn authenticated_data(&self) -> Vec<u8> {
        if let PacketType::WhoAreYou { .. } = self.flag {
            return Vec::new();
        }

        // all else requires the encoded header
        self.encode()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacketType {
    /// An ordinary message.
    Message(MessageNonce),
    /// A WHOAREYOU packet.
    WhoAreYou {
        /// The request nonce the WHOAREYOU references.
        request_nonce: MessageNonce,
        /// The ID Nonce to be verified.
        id_nonce: IdNonce,
        /// The local node's current ENR sequence number.
        enr_seq: u64,
    },
    /// A handshake message.
    Handshake {
        /// The nonce of the message.
        message_nonce: MessageNonce,
        /// Id-nonce signature that matches the WHOAREYOU request.
        id_nonce_sig: Vec<u8>,
        /// The ephemeral public key of the handshake.
        ephem_pubkey: Vec<u8>,
        /// The ENR record of the node if the WHOAREYOU request is out-dated.
        enr_record: Option<Enr>,
    },
}

impl Into<u8> for &PacketType {
    fn into(self) -> u8 {
        match self {
            PacketType::Message(_) => 0,
            PacketType::WhoAreYou { .. } => 1,
            PacketType::Handshake { .. } => 2,
        }
    }
}

impl PacketType {
    /// Encodes the packet type into its corresponding auth_data.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PacketType::Message(message_nonce) => message_nonce.to_vec(),
            PacketType::WhoAreYou {
                request_nonce,
                id_nonce,
                enr_seq,
            } => {
                let mut auth_data = Vec::with_capacity(52);
                auth_data.extend_from_slice(request_nonce);
                auth_data.extend_from_slice(id_nonce);
                auth_data.extend_from_slice(&enr_seq.to_be_bytes());
                debug_assert_eq!(auth_data.len(), 52);
                auth_data
            }
            PacketType::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            } => {
                let sig_size = id_nonce_sig.len();
                let pubkey_size = ephem_pubkey.len();
                let node_record = enr_record.as_ref().map(|enr| rlp::encode(enr));
                let expected_len = 15
                    + sig_size
                    + pubkey_size
                    + node_record.as_ref().map(|x| x.len()).unwrap_or_default();

                let mut auth_data = Vec::with_capacity(expected_len);
                auth_data.extend_from_slice(&VERSION.to_be_bytes());
                auth_data.extend_from_slice(message_nonce);
                auth_data.extend_from_slice(&sig_size.to_be_bytes());
                auth_data.extend_from_slice(&pubkey_size.to_be_bytes());
                auth_data.extend_from_slice(id_nonce_sig);
                auth_data.extend_from_slice(ephem_pubkey);
                if let Some(node_record) = node_record {
                    auth_data.extend_from_slice(&node_record);
                }

                debug_assert_eq!(auth_data.len(), expected_len);

                auth_data
            }
        }
    }

    pub fn is_whoareyou(&self) -> bool {
        match self {
            PacketType::WhoAreYou { .. } => true,
            _ => false,
        }
    }

    /// Decodes auth data, given the flag byte.
    pub fn decode(flag: u8, auth_data: &[u8]) -> Result<Self, PacketError> {
        match flag {
            0 => {
                // Decoding a message packet
                // This should only contain a 12 byte nonce.
                if auth_data.len() != MESSAGE_NONCE_LENGTH {
                    return Err(PacketError::InvalidAuthDataSize);
                }
                Ok(PacketType::Message(
                    auth_data.try_into().expect("Must have the correct length"),
                ))
            }
            1 => {
                // Decoding a WHOAREYOU packet
                // This must be 52 bytes long.
                if auth_data.len() != 52 {
                    return Err(PacketError::InvalidAuthDataSize);
                }
                let request_nonce: MessageNonce = auth_data[..MESSAGE_NONCE_LENGTH]
                    .try_into()
                    .expect("MESSAGE_NONCE_LENGTH is the correct size");
                let id_nonce: IdNonce = auth_data
                    [MESSAGE_NONCE_LENGTH..MESSAGE_NONCE_LENGTH + ID_NONCE_LENGTH]
                    .try_into()
                    .expect("ID_NONCE_LENGTH must be the correct size");
                let enr_seq = u64::from_be_bytes(
                    auth_data[MESSAGE_NONCE_LENGTH + ID_NONCE_LENGTH..]
                        .try_into()
                        .expect("The length of the authdata must be 52 bytes"),
                );

                Ok(PacketType::WhoAreYou {
                    request_nonce,
                    id_nonce,
                    enr_seq,
                })
            }
            2 => {
                // Decoding a Handshake packet
                // Start by decoding the header
                if auth_data.len() < 3 + MESSAGE_NONCE_LENGTH {
                    // The auth_data header is too short
                    return Err(PacketError::InvalidAuthDataSize);
                }

                // verify the version
                if auth_data[0] != VERSION {
                    return Err(PacketError::InvalidVersion(auth_data[0]));
                }

                // decode the lengths
                let message_nonce: MessageNonce = auth_data[1..MESSAGE_NONCE_LENGTH + 1]
                    .try_into()
                    .expect("MESSAGE_NONCE_LENGTH is the correct size");
                let sig_size = auth_data[MESSAGE_NONCE_LENGTH + 1];
                let eph_key_size = auth_data[MESSAGE_NONCE_LENGTH + 2];

                let sig_key_size = (sig_size + eph_key_size) as usize;
                // verify the auth data length
                if auth_data.len() < 3 + MESSAGE_NONCE_LENGTH + sig_key_size {
                    return Err(PacketError::InvalidAuthDataSize);
                }

                let remaining_data = &auth_data[MESSAGE_NONCE_LENGTH + 3..];

                let id_nonce_sig = remaining_data[0..sig_size as usize].to_vec();
                let ephem_pubkey = remaining_data[sig_size as usize..sig_key_size].to_vec();

                let enr_record = if remaining_data.len() > sig_key_size {
                    Some(
                        rlp::decode::<Enr>(&remaining_data[sig_key_size..])
                            .map_err(PacketError::InvalidEnr)?,
                    )
                } else {
                    None
                };

                Ok(PacketType::Handshake {
                    message_nonce,
                    id_nonce_sig,
                    ephem_pubkey,
                    enr_record,
                })
            }
            _ => Err(PacketError::UnknownPacket),
        }
    }
}

/// The implementation of creating, encoding and decoding raw packets in the discv5.1 system.
//
// NOTE: We perform the encryption and decryption when we are encoding/decoding as this is
// performed in its own task in practice. The Handler can create the messages without the overhead
// of encryption/decryption and send them off to the send/recv tasks to perform the
// encryption/decryption.
impl Packet {
    /// Creates an ordinary message packet.
    pub fn new_message(src_id: NodeId, nonce: MessageNonce, ciphertext: Vec<u8>) -> Self {
        let iv: u128 = rand::random();

        let header = PacketHeader {
            src_id,
            flag: PacketType::Message(nonce),
        };

        Packet {
            iv,
            header,
            message: ciphertext,
        }
    }

    pub fn new_whoareyou(
        src_id: NodeId,
        request_nonce: MessageNonce,
        id_nonce: IdNonce,
        enr_seq: u64,
    ) -> Self {
        let iv: u128 = rand::random();

        let header = PacketHeader {
            src_id,
            flag: PacketType::WhoAreYou {
                request_nonce,
                id_nonce,
                enr_seq,
            },
        };

        Packet {
            iv,
            header,
            message: Vec::new(),
        }
    }

    pub fn new_authheader(
        src_id: NodeId,
        message_nonce: MessageNonce,
        id_nonce_sig: Vec<u8>,
        ephem_pubkey: Vec<u8>,
        enr_record: Option<Enr>,
    ) -> Self {
        let iv: u128 = rand::random();

        let header = PacketHeader {
            src_id,
            flag: PacketType::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            },
        };

        Packet {
            iv,
            header,
            message: Vec::new(),
        }
    }

    /// Generates a Packet::Random given a `tag`.
    pub fn new_random(src_id: &NodeId) -> Result<Self, &'static str> {
        let mut ciphertext = [0u8; 44];
        rand::thread_rng()
            .try_fill(&mut ciphertext[..])
            .map_err(|_| "PRNG failed")?;

        let message_nonce: MessageNonce = rand::random();

        Ok(Self::new_message(
            *src_id,
            message_nonce,
            ciphertext.to_vec(),
        ))
    }

    /// Returns true if the packet is a WHOAREYOU packet.
    pub fn is_whoareyou(&self) -> bool {
        match &self.header.flag {
            PacketType::WhoAreYou { .. } => true,
            PacketType::Message(_) | PacketType::Handshake { .. } => false,
        }
    }

    /// Returns the message nonce if one exists.
    pub fn message_nonce(&self) -> Option<&MessageNonce> {
        match &self.header.flag {
            PacketType::Message(message_nonce) => Some(message_nonce),
            PacketType::WhoAreYou { .. } => None,
            PacketType::Handshake { message_nonce, .. } => Some(message_nonce),
        }
    }

    /// Encodes a packet to bytes and performs the AES-CTR encryption.
    pub fn encode(self, dst_id: &NodeId) -> Vec<u8> {
        let header = self.generate_header(dst_id);
        let mut buf = Vec::with_capacity(IV_LENGTH + header.len() + self.message.len());
        buf.extend_from_slice(&self.iv.to_be_bytes());
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&self.message);
        buf
    }

    /// Decodes a packet (data) given our local source id (src_key).
    ///
    /// The source key is the first 16 bytes of our local node id.
    pub fn decode(src_key: &[u8; 16], data: &[u8]) -> Result<Self, PacketError> {
        // The smallest packet must be at least this large
        if data.len() < IV_LENGTH + STATIC_HEADER_LENGTH + MESSAGE_NONCE_LENGTH {
            return Err(PacketError::TooSmall);
        }

        // attempt to decrypt the static header
        let iv = data[..IV_LENGTH].to_vec();

        /* Decryption is done inline
         *
         * This was split into its own library, but brought back to allow re-use of the cipher when
         * performing the decryption
         */
        let key = GenericArray::from(*src_key);
        let nonce = GenericArray::clone_from_slice(&iv);
        let mut cipher = Aes128Ctr::new(&key, &nonce);

        // Take the static header content
        let mut static_header = data[IV_LENGTH..STATIC_HEADER_LENGTH].to_vec();
        cipher.apply_keystream(&mut static_header);

        // double check the size
        if static_header.len() != STATIC_HEADER_LENGTH {
            return Err(PacketError::HeaderLengthInvalid(static_header.len()));
        }

        // Check the protocol id
        if &static_header[..8] != PROTOCOL_ID.as_bytes() {
            return Err(PacketError::HeaderDecryptionFailed);
        }

        // The decryption was successful, decrypt the remaining header
        let auth_data_size = u16::from_be_bytes(
            static_header[STATIC_HEADER_LENGTH - 2..]
                .try_into()
                .expect("Can only be 2 bytes in size"),
        );

        let remaining_data = data[STATIC_HEADER_LENGTH..].to_vec();
        if auth_data_size as usize > remaining_data.len() {
            return Err(PacketError::InvalidAuthDataSize);
        }

        let mut auth_data =
            data[IV_LENGTH + STATIC_HEADER_LENGTH..auth_data_size as usize].to_vec();
        cipher.apply_keystream(&mut auth_data);

        let flag = PacketType::decode(static_header[40], &auth_data)?;
        let src_id = NodeId::parse(&static_header[8..40]).expect("This is exactly 32 bytes");

        let header = PacketHeader { src_id, flag };

        // Any remaining bytes are message data
        let message = data[IV_LENGTH + STATIC_HEADER_LENGTH + auth_data_size as usize..].to_vec();

        if !message.is_empty() && header.flag.is_whoareyou() {
            // do not allow extra bytes being sent in WHOAREYOU messages
            return Err(PacketError::UnknownPacket);
        }

        Ok(Packet {
            iv: u128::from_be_bytes(iv[..].try_into().expect("IV_LENGTH must be 16 bytes")),
            header,
            message,
        })
    }

    /// Creates the masked header of a packet performing the required AES-CTR encryption.
    fn generate_header(&self, dst_id: &NodeId) -> Vec<u8> {
        let mut header_bytes = self.header.encode();

        /* Encryption is done inline
         *
         * This was split into its own library, but brought back to allow re-use of the cipher when
         * performing decryption
         */
        let mut key = GenericArray::clone_from_slice(&dst_id.raw()[..16]);
        let mut nonce = GenericArray::clone_from_slice(&self.iv.to_be_bytes());

        let mut cipher = Aes128Ctr::new(&key, &nonce);
        cipher.apply_keystream(&mut header_bytes);
        key.zeroize();
        nonce.zeroize();
        header_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::{CombinedKey, EnrKey, EnrPublicKey};
    use rand;
    use simple_logger;

    fn hex_decode(x: &'static str) -> Vec<u8> {
        hex::decode(x).unwrap()
    }

    fn node_key_1() -> CombinedKey {
        CombinedKey::secp256k1_from_bytes(&mut hex_decode(
            "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f",
        ))
        .unwrap()
    }

    fn node_key_2() -> CombinedKey {
        CombinedKey::secp256k1_from_bytes(&mut hex_decode(
            "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628",
        ))
        .unwrap()
    }

    #[test]
    fn test_encode_random_packet() {
        let node_id_a: NodeId = node_key_1().public().into();
        let node_id_b: NodeId = node_key_2().public().into();

        let expected_result = hex::decode("0000000000000000000000000000000b4f3ab1857252d94edf25b8bda34d42d8260ec07cfbb0b826e8067831b5af17ad5566dc48f0d48d73b9942b9bb5d5d5c9e08a3585038c4d010101010101010101010101").unwrap();
        let iv = 11u128;
        let header = PacketHeader {
            src_id: node_id_a,
            flag: PacketType::Message([12u8; MESSAGE_NONCE_LENGTH]),
        };
        let message = [1u8; 12].to_vec();
        let packet = Packet {
            iv,
            header,
            message,
        };

        let encoded = packet.encode(&node_id_b);
        assert_eq!(expected_result, encoded);
    }

    #[test]
    fn ref_test_encode_whoareyou_packet() {
        // reference input
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();
        let request_nonce: MessageNonce = hex_decode("0102030405060708090a0b0c")[..]
            .try_into()
            .unwrap();
        let id_nonce: IdNonce =
            hex_decode("0102030405060708090a0b0c0d0e0f1000000000000000000000000000000000")[..]
                .try_into()
                .unwrap();
        let enr_seq = 0u64;
        let iv = 0u128;

        // expected hex output
        let expected_output = hex::decode("00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3ecb9ad5e368892ec562137bf19c6d0a9191a5651c4f415117bdfa0c7ab86af62b7a9784eceb28008d03ede83bd1369631f9f3d8da0b45").unwrap();

        let header = PacketHeader {
            src_id,
            flag: PacketType::WhoAreYou {
                request_nonce,
                id_nonce,
                enr_seq,
            },
        };

        let packet = Packet {
            iv,
            header,
            message: Vec::new(),
        };

        assert_eq!(packet.encode(&dst_id), expected_output);
    }

    #[test]
    fn ref_test_encode_handshake_packet() {
        // reference input
        let src_id = NodeId::parse(&vec![3; 32]).unwrap();
        let dst_id = NodeId::parse(&vec![4; 32]).unwrap();
        let message_nonce: MessageNonce = [52u8; MESSAGE_NONCE_LENGTH];
        let id_nonce_sig = vec![5u8; 64];
        let ephem_pubkey = vec![6u8; 33];
        let enr_record = None;
        let iv = 0u128;

        let expected_output = hex::decode("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903f8cc8c27b5af763c446acd2749fe8ea0e551b1c44264ab92bc0b3c9b26293e1ba4fed9128f3c3645301e8e119f179c658367636db840b35608c01ee67edff2cffa424b219940a81cf2fb9b66068b1cf96862a17d353e22524fbdcdebc609f85cbd58ebe7a872b01e24a3829b97dd5875e8ffbc4eea81b856570fbf23885c674867ab00320294a41732891457969a0f14d11c995668858b2ad731aa7836888020e2ccc6e0e5776d0d4bc4439161798565a4159aa8620992fb51dcb275c4f755c8b8030c82918898f1ac387f606852a5d12a2d94b8ccb3ba55558229867dc13bfa3648").unwrap();

        let header = PacketHeader {
            src_id,
            flag: PacketType::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            },
        };

        let packet = Packet {
            iv,
            header,
            message: Vec::new(),
        };
        let encoded = packet.encode(&dst_id);
        println!("{:?}", hex::encode(&encoded));
        assert_eq!(encoded, expected_output);
    }

    /*
    #[test]
    fn ref_test_encode_message_packet() {
        // reference input
        let tag_raw =
            hex::decode("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
                .unwrap();
        let auth_tag_raw = hex::decode("27b5af763c446acd2749fe8e").unwrap();
        let message_ciphertext = hex::decode("a5d12a2d94b8ccb3ba55558229867dc13bfa3648").unwrap();

        // expected hex output
        let expected_output = hex::decode("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f421079038c27b5af763c446acd2749fe8ea5d12a2d94b8ccb3ba55558229867dc13bfa3648").unwrap();

        let mut tag = [0u8; TAG_LENGTH];
        tag.copy_from_slice(&tag_raw);
        let mut auth_tag = [0u8; AUTH_TAG_LENGTH];
        auth_tag.copy_from_slice(&auth_tag_raw);

        let packet = Packet::Message {
            tag,
            auth_tag,
            message: message_ciphertext,
        };

        assert_eq!(packet.encode(), expected_output);
    }

    /* This section provides functionality testing of the packets */

    #[test]
    fn encode_decode_random_packet() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let tag = hash256_to_fixed_array("test-tag");
        let auth_tag: [u8; AUTH_TAG_LENGTH] = rand::random();
        let random_magic: Magic = rand::random();
        let random_data: [u8; 44] = [17; 44];

        let packet = Packet::RandomPacket {
            tag: tag.clone(),
            auth_tag: auth_tag.clone(),
            data: random_data.to_vec(),
        };

        let encoded_packet = packet.encode();
        let decoded_packet = Packet::decode(&encoded_packet, &random_magic).unwrap();
        let expected_packet = Packet::Message {
            tag,
            auth_tag,
            message: random_data.to_vec(),
        };

        assert_eq!(decoded_packet, expected_packet);
    }

    #[test]
    fn encode_decode_whoareyou_packet() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let magic = hash256_to_fixed_array("magic");
        let id_nonce: [u8; ID_NONCE_LENGTH] = rand::random();
        let auth_tag: [u8; AUTH_TAG_LENGTH] = rand::random();
        let enr_seq: u64 = rand::random();

        let packet = Packet::WhoAreYou {
            magic,
            auth_tag,
            id_nonce,
            enr_seq,
        };

        let encoded_packet = packet.clone().encode();
        let decoded_packet = Packet::decode(&encoded_packet, &magic).unwrap();

        assert_eq!(decoded_packet, packet);
    }

    #[test]
    fn encode_decode_auth_packet() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let tag = hash256_to_fixed_array("test-tag");
        let magic = hash256_to_fixed_array("test-magic");

        // auth header data
        let auth_tag: [u8; AUTH_TAG_LENGTH] = rand::random();
        let id_nonce: [u8; ID_NONCE_LENGTH] = rand::random();
        let ephemeral_pubkey = enr::CombinedKey::generate_secp256k1().public().encode();
        let auth_response: [u8; 32] = rand::random();
        let auth_response = auth_response.to_vec();

        let auth_header = AuthHeader {
            id_nonce,
            auth_tag,
            auth_scheme_name: "gcm",
            ephemeral_pubkey,
            auth_response,
        };

        let message: [u8; 16] = rand::random();
        let message = message.to_vec();

        let packet = Packet::AuthMessage {
            tag,
            auth_header,
            message,
        };

        let encoded_packet = packet.clone().encode();
        let decoded_packet = Packet::decode(&encoded_packet, &magic).unwrap();

        assert_eq!(decoded_packet, packet);
    }
    */
}
