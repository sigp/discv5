use derive_more::{Display, From};
use rlp::{DecoderError, Rlp};
use std::convert::{TryFrom, TryInto};

mod notification;
mod request;
mod response;

pub use notification::{RelayInitNotification, RelayMsgNotification};
pub use request::{Request, RequestBody, RequestId};
pub use response::{Response, ResponseBody};

/// Message type IDs.
#[derive(Debug)]
#[repr(u8)]
pub enum MessageType {
    Ping = 1,
    Pong = 2,
    FindNode = 3,
    Nodes = 4,
    TalkReq = 5,
    TalkResp = 6,
    RelayInit = 7,
    RelayMsg = 8,
}

impl TryFrom<u8> for MessageType {
    type Error = DecoderError;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            1 => Ok(MessageType::Ping),
            2 => Ok(MessageType::Pong),
            3 => Ok(MessageType::FindNode),
            4 => Ok(MessageType::Nodes),
            5 => Ok(MessageType::TalkReq),
            6 => Ok(MessageType::TalkResp),
            7 => Ok(MessageType::RelayInit),
            8 => Ok(MessageType::RelayMsg),
            _ => Err(DecoderError::Custom("Unknown RPC message type")),
        }
    }
}

/// The payload of message containers SessionMessage, Message or Handshake type.
pub trait Payload
where
    Self: Sized,
{
    /// Matches a payload type to its message type id.
    fn msg_type(&self) -> u8;
    /// Encodes a message to RLP-encoded bytes.
    fn encode(self) -> Vec<u8>;
    /// Decodes RLP-encoded bytes into a message.
    fn decode(msg_type: u8, rlp: &Rlp<'_>) -> Result<Self, DecoderError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Display, From)]
/// A combined type representing the messages which are the payloads of packets.
pub enum Message {
    /// A request, which contains its [`RequestId`].
    #[display(fmt = "{_0}")]
    Request(Request),

    /// A Response, which contains the [`RequestId`] of its associated request.
    #[display(fmt = "{_0}")]
    Response(Response),

    /// Unicast notifications.
    ///
    /// A [`RelayInitNotification`].
    #[display(fmt = "{_0}")]
    RelayInitNotification(RelayInitNotification),
    /// A [`RelayMsgNotification`].
    #[display(fmt = "{_0}")]
    RelayMsgNotification(RelayMsgNotification),
}

#[allow(dead_code)]
impl Message {
    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Request(request) => request.encode(),
            Self::Response(response) => response.encode(),
            Self::RelayInitNotification(notif) => notif.encode(),
            Self::RelayMsgNotification(notif) => notif.encode(),
        }
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecoderError> {
        if data.len() < 3 {
            return Err(DecoderError::RlpIsTooShort);
        }
        let msg_type = data[0];

        let rlp = rlp::Rlp::new(&data[1..]);

        match msg_type.try_into()? {
            MessageType::Ping | MessageType::FindNode | MessageType::TalkReq => {
                Ok(Request::decode(msg_type, &rlp)?.into())
            }
            MessageType::Pong | MessageType::Nodes | MessageType::TalkResp => {
                Ok(Response::decode(msg_type, &rlp)?.into())
            }
            MessageType::RelayInit => Ok(RelayInitNotification::decode(msg_type, &rlp)?.into()),
            MessageType::RelayMsg => Ok(RelayMsgNotification::decode(msg_type, &rlp)?.into()),
        }
    }

    pub fn msg_type(&self) -> String {
        match self {
            Self::Request(r) => format!("request type {}", r.msg_type()),
            Self::Response(r) => format!("response type {}", r.msg_type()),
            Self::RelayInitNotification(n) => format!("notification type {}", n.msg_type()),
            Self::RelayMsgNotification(n) => format!("notification type {}", n.msg_type()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::MESSAGE_NONCE_LENGTH;
    use enr::{CombinedKey, Enr, EnrBuilder};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ref_test_encode_request_ping() {
        // reference input
        let id = RequestId(vec![1]);
        let enr_seq = 1;
        let message = Message::Request(Request {
            id,
            body: RequestBody::Ping { enr_seq },
        });

        // expected hex output
        let expected_output = hex::decode("01c20101").unwrap();

        dbg!(hex::encode(message.clone().encode()));
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_request_findnode() {
        // reference input
        let id = RequestId(vec![1]);
        let distances = vec![256];
        let message = Message::Request(Request {
            id,
            body: RequestBody::FindNode { distances },
        });

        // expected hex output
        let expected_output = hex::decode("03c501c3820100").unwrap();
        dbg!(hex::encode(message.clone().encode()));

        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_ping() {
        // reference input
        let id = RequestId(vec![1]);
        let enr_seq = 1;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let port = 5000;
        let message = Message::Response(Response {
            id,
            body: ResponseBody::Pong { enr_seq, ip, port },
        });

        // expected hex output
        let expected_output = hex::decode("02ca0101847f000001821388").unwrap();

        dbg!(hex::encode(message.clone().encode()));
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes_empty() {
        // reference input
        let id = RequestId(vec![1]);
        let total = 1;

        // expected hex output
        let expected_output = hex::decode("04c30101c0").unwrap();

        let message = Message::Response(Response {
            id,
            body: ResponseBody::Nodes {
                total,
                nodes: vec![],
            },
        });
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes() {
        // reference input
        let id = RequestId(vec![1]);
        let total = 1;

        let enr = "-HW4QCjfjuCfSmIJHxqLYfGKrSz-Pq3G81DVJwd_muvFYJiIOkf0bGtJu7kZVCOPnhSTMneyvR4MRbF3G5TNB4wy2ssBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr<CombinedKey>>().unwrap();
        // expected hex output
        let expected_output = hex::decode("04f87b0101f877f875b84028df8ee09f4a62091f1a8b61f18aad2cfe3eadc6f350d527077f9aebc56098883a47f46c6b49bbb91954238f9e14933277b2bd1e0c45b1771b94cd078c32dacb0182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();

        let message = Message::Response(Response {
            id,
            body: ResponseBody::Nodes {
                total,
                nodes: vec![enr],
            },
        });
        dbg!(hex::encode(message.clone().encode()));
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes_multiple() {
        // reference input
        let id = RequestId(vec![1]);
        let total = 1;
        let enr = "enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr<CombinedKey>>().unwrap();

        let enr2 = "enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU".parse::<Enr<CombinedKey>>().unwrap();

        // expected hex output
        let expected_output = hex::decode("04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235").unwrap();

        let message = Message::Response(Response {
            id,
            body: ResponseBody::Nodes {
                total,
                nodes: vec![enr, enr2],
            },
        });
        dbg!(hex::encode(message.clone().encode()));
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_decode_response_nodes_multiple() {
        let input = hex::decode("04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235").unwrap();

        let expected_enr1 = "enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr<CombinedKey>>().unwrap();
        let expected_enr2 = "enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU".parse::<Enr<CombinedKey>>().unwrap();

        let decoded = Message::decode(&input).unwrap();

        match decoded {
            Message::Response(response) => match response.body {
                ResponseBody::Nodes { total, nodes } => {
                    assert_eq!(total, 1);
                    assert_eq!(nodes[0], expected_enr1);
                    assert_eq!(nodes[1], expected_enr2);
                }
                _ => panic!("Invalid decoding"),
            },
            _ => panic!("Invalid decoding"),
        }
    }

    #[test]
    fn encode_decode_ping_request() {
        let id = RequestId(vec![1]);
        let request = Message::Request(Request {
            id,
            body: RequestBody::Ping { enr_seq: 15 },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ping_response() {
        let id = RequestId(vec![1]);
        let request = Message::Response(Response {
            id,
            body: ResponseBody::Pong {
                enr_seq: 15,
                ip: "127.0.0.1".parse().unwrap(),
                port: 80,
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ping_response_ipv4_mapped() {
        let id = RequestId(vec![1]);
        let request = Message::Response(Response {
            id: id.clone(),
            body: ResponseBody::Pong {
                enr_seq: 15,
                ip: IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()),
                port: 80,
            },
        });

        let encoded = request.encode();
        let decoded = Message::decode(&encoded).unwrap();
        let expected = Message::Response(Response {
            id,
            body: ResponseBody::Pong {
                enr_seq: 15,
                ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 80,
            },
        });

        assert_eq!(expected, decoded);
    }

    #[test]
    fn encode_decode_ping_response_ipv6_loopback() {
        let id = RequestId(vec![1]);
        let request = Message::Response(Response {
            id,
            body: ResponseBody::Pong {
                enr_seq: 15,
                ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                port: 80,
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_find_node_request() {
        let id = RequestId(vec![1]);
        let request = Message::Request(Request {
            id,
            body: RequestBody::FindNode {
                distances: vec![12],
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_nodes_response() {
        let key = CombinedKey::generate_secp256k1();
        let enr1 = EnrBuilder::new("v4")
            .ip4("127.0.0.1".parse().unwrap())
            .udp4(500)
            .build(&key)
            .unwrap();
        let enr2 = EnrBuilder::new("v4")
            .ip4("10.0.0.1".parse().unwrap())
            .tcp4(8080)
            .build(&key)
            .unwrap();
        let enr3 = EnrBuilder::new("v4")
            .ip("10.4.5.6".parse().unwrap())
            .build(&key)
            .unwrap();

        let enr_list = vec![enr1, enr2, enr3];
        let id = RequestId(vec![1]);
        let request = Message::Response(Response {
            id,
            body: ResponseBody::Nodes {
                total: 1,
                nodes: enr_list,
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_talk_request() {
        let id = RequestId(vec![1]);
        let request = Message::Request(Request {
            id,
            body: RequestBody::TalkReq {
                protocol: vec![17u8; 32],
                request: vec![1, 2, 3],
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn test_encode_decode_relay_init() {
        // generate a new enr key for the initiator
        let enr_key = CombinedKey::generate_secp256k1();
        // construct the initiator's ENR
        let inr_enr = EnrBuilder::new("v4").build(&enr_key).unwrap();

        // generate a new enr key for the target
        let enr_key_tgt = CombinedKey::generate_secp256k1();
        // construct the target's ENR
        let tgt_enr = EnrBuilder::new("v4").build(&enr_key_tgt).unwrap();
        let tgt_node_id = tgt_enr.node_id();

        let nonce_bytes = hex::decode("47644922f5d6e951051051ac").unwrap();
        let mut nonce = [0u8; MESSAGE_NONCE_LENGTH];
        nonce[MESSAGE_NONCE_LENGTH - nonce_bytes.len()..].copy_from_slice(&nonce_bytes);

        let notif = RelayInitNotification::new(inr_enr, tgt_node_id, nonce);
        let msg = Message::RelayInitNotification(notif);

        let encoded_msg = msg.clone().encode();
        let decoded_msg = Message::decode(&encoded_msg).expect("Should decode");

        assert_eq!(msg, decoded_msg);
    }

    #[test]
    fn test_enocde_decode_relay_msg() {
        // generate a new enr key for the initiator
        let enr_key = CombinedKey::generate_secp256k1();
        // construct the initiator's ENR
        let inr_enr = EnrBuilder::new("v4").build(&enr_key).unwrap();

        let nonce_bytes = hex::decode("9951051051aceb").unwrap();
        let mut nonce = [0u8; MESSAGE_NONCE_LENGTH];
        nonce[MESSAGE_NONCE_LENGTH - nonce_bytes.len()..].copy_from_slice(&nonce_bytes);

        let notif = RelayMsgNotification::new(inr_enr, nonce);
        let msg = Message::RelayMsgNotification(notif);

        let encoded_msg = msg.clone().encode();
        let decoded_msg = Message::decode(&encoded_msg).expect("Should decode");

        assert_eq!(msg, decoded_msg);
    }
}
