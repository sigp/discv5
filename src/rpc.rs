use enr::{CombinedKey, Enr};
use log::debug;
use rlp::{DecoderError, RlpStream};
use std::net::IpAddr;

type TopicHash = [u8; 32];

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolMessage {
    pub id: u64,
    pub body: RpcType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RpcType {
    Request(Request),
    Response(Response),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Ping { enr_seq: u64 },
    FindNode { distance: u64 },
    Ticket { topic: TopicHash },
    RegisterTopic { ticket: Vec<u8> },
    TopicQuery { topic: TopicHash },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    Ping {
        enr_seq: u64,
        ip: IpAddr,
        port: u16,
    },
    Nodes {
        total: u64,
        nodes: Vec<Enr<CombinedKey>>,
    },
    Ticket {
        ticket: Vec<u8>,
        wait_time: u64,
    },
    RegisterTopic {
        registered: bool,
    },
}

impl Response {
    /// Determines if the response is a valid response to the given request.
    pub fn match_request(&self, req: &Request) -> bool {
        match self {
            Response::Ping { .. } => {
                if let Request::Ping { .. } = req {
                    true
                } else {
                    false
                }
            }
            Response::Nodes { .. } => match req {
                Request::FindNode { .. } => true,
                Request::TopicQuery { .. } => true,
                _ => false,
            },
            Response::Ticket { .. } => {
                if let Request::Ticket { .. } = req {
                    true
                } else {
                    false
                }
            }
            Response::RegisterTopic { .. } => {
                if let Request::TopicQuery { .. } = req {
                    true
                } else {
                    false
                }
            }
        }
    }
}

impl std::fmt::Display for RpcType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RpcType::Request(request) => write!(f, "{:?}", request),
            RpcType::Response(response) => write!(f, "{}", response),
        }
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Response::Ping { enr_seq, ip, port } => write!(
                f,
                "PING Response: Enr-seq: {}, Ip: {:?},  Port: {}",
                enr_seq, ip, port
            ),
            Response::Nodes { total, nodes } => {
                let _ = write!(f, "NODES Response: total: {}, Nodes: [", total);
                let mut first = true;
                for id in nodes {
                    if !first {
                        write!(f, ", {}", id)?;
                    } else {
                        write!(f, "{}", id)?;
                    }
                    first = false;
                }

                write!(f, "]")
            }
            Response::Ticket { ticket, wait_time } => write!(
                f,
                "TICKET Response: Ticket: {:?}, Wait time: {}",
                ticket, wait_time
            ),
            Response::RegisterTopic { registered } => {
                write!(f, "REGTOPIC Response: Registered: {}", registered)
            }
        }
    }
}

impl std::fmt::Display for ProtocolMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Message: Id: {}, Body: {}", self.id, self.body)
    }
}

impl ProtocolMessage {
    pub fn msg_type(&self) -> u8 {
        match &self.body {
            RpcType::Request(request) => match request {
                Request::Ping { .. } => 1,
                Request::FindNode { .. } => 3,
                Request::Ticket { .. } => 5,
                Request::RegisterTopic { .. } => 7,
                Request::TopicQuery { .. } => 9,
            },
            RpcType::Response(response) => match response {
                Response::Ping { .. } => 2,
                Response::Nodes { .. } => 4,
                Response::Ticket { .. } => 6,
                Response::RegisterTopic { .. } => 8,
            },
        }
    }

    /// Encodes a ProtocolMessage to RLP-encoded bytes.
    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10);
        let msg_type = self.msg_type();
        buf.push(msg_type);
        let id = &self.id;
        match self.body {
            RpcType::Request(request) => match request {
                Request::Ping { enr_seq } => {
                    let mut s = RlpStream::new();
                    s.begin_list(2);
                    s.append(id);
                    s.append(&enr_seq);
                    buf.extend_from_slice(&s.drain());
                    buf
                }
                Request::FindNode { distance } => {
                    let mut s = RlpStream::new();
                    s.begin_list(2);
                    s.append(id);
                    s.append(&distance);
                    buf.extend_from_slice(&s.drain());
                    buf
                }
                Request::Ticket { topic } => {
                    let mut s = RlpStream::new();
                    s.begin_list(2);
                    s.append(id);
                    s.append(&topic.to_vec());
                    buf.extend_from_slice(&s.drain());
                    buf
                }
                Request::RegisterTopic { ticket } => {
                    let mut s = RlpStream::new();
                    s.begin_list(2);
                    s.append(id);
                    s.append(&ticket.to_vec());
                    buf.extend_from_slice(&s.drain());
                    buf
                }
                Request::TopicQuery { topic } => {
                    let mut s = RlpStream::new();
                    s.begin_list(2);
                    s.append(id);
                    s.append(&topic.to_vec());
                    buf.extend_from_slice(&s.drain());
                    buf
                }
            },
            RpcType::Response(response) => match response {
                Response::Ping { enr_seq, ip, port } => {
                    let ip_bytes = match ip {
                        IpAddr::V4(addr) => addr.octets().to_vec(),
                        IpAddr::V6(addr) => addr.octets().to_vec(),
                    };
                    let mut s = RlpStream::new();
                    s.begin_list(4);
                    s.append(id);
                    s.append(&enr_seq);
                    s.append(&ip_bytes);
                    s.append(&port);
                    buf.extend_from_slice(&s.drain());
                    buf
                }
                Response::Nodes { total, nodes } => {
                    let mut s = RlpStream::new();
                    s.begin_list(3);
                    s.append(id);
                    s.append(&total);

                    if nodes.is_empty() {
                        s.begin_list(0);
                    } else {
                        s.begin_list(nodes.len());
                        for node in nodes {
                            s.append(&node);
                        }
                    }
                    buf.extend_from_slice(&s.drain());
                    buf
                }
                Response::Ticket { ticket, wait_time } => {
                    let mut s = RlpStream::new();
                    s.begin_list(3);
                    s.append(id);
                    s.append(&ticket.to_vec());
                    s.append(&wait_time);
                    buf.extend_from_slice(&s.drain());
                    buf
                }
                Response::RegisterTopic { registered } => {
                    let mut s = RlpStream::new();
                    s.begin_list(2);
                    s.append(id);
                    s.append(&registered);
                    buf.extend_from_slice(&s.drain());
                    buf
                }
            },
        }
    }

    pub fn decode(data: Vec<u8>) -> Result<Self, DecoderError> {
        if data.len() < 3 {
            return Err(DecoderError::RlpIsTooShort);
        }

        let msg_type = data[0];

        let rlp = rlp::Rlp::new(&data[1..]);

        let list_len = rlp.item_count().and_then(|size| {
            if size < 2 {
                Err(DecoderError::RlpIncorrectListLen)
            } else {
                Ok(size)
            }
        })?;

        let id = rlp.val_at::<u64>(0)?;

        let body = match msg_type {
            1 => {
                // PingRequest
                if list_len != 2 {
                    debug!(
                        "Ping Request has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                RpcType::Request(Request::Ping {
                    enr_seq: rlp.val_at::<u64>(1)?,
                })
            }
            2 => {
                // PingResponse
                if list_len != 4 {
                    debug!(
                        "Ping Response has an invalid RLP list length. Expected 4, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let ip_bytes = rlp.val_at::<Vec<u8>>(2)?;
                let ip = match ip_bytes.len() {
                    4 => {
                        let mut ip = [0u8; 4];
                        ip.copy_from_slice(&ip_bytes);
                        IpAddr::from(ip)
                    }
                    16 => {
                        let mut ip = [0u8; 16];
                        ip.copy_from_slice(&ip_bytes);
                        IpAddr::from(ip)
                    }
                    _ => {
                        debug!("Ping Response has incorrect byte length for IP");
                        return Err(DecoderError::RlpIncorrectListLen);
                    }
                };
                let port = rlp.val_at::<u16>(3)?;
                RpcType::Response(Response::Ping {
                    enr_seq: rlp.val_at::<u64>(1)?,
                    ip,
                    port,
                })
            }
            3 => {
                // FindNodeRequest
                if list_len != 2 {
                    debug!(
                        "FindNode Request has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                RpcType::Request(Request::FindNode {
                    distance: rlp.val_at::<u64>(1)?,
                })
            }
            4 => {
                // NodesResponse
                if list_len != 3 {
                    debug!(
                        "Nodes Response has an invalid RLP list length. Expected 3, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }

                let nodes = {
                    let enr_list_rlp = rlp.at(2)?;
                    if enr_list_rlp.is_empty() {
                        // no records
                        vec![]
                    } else {
                        enr_list_rlp.as_list::<Enr<CombinedKey>>()?
                    }
                };
                RpcType::Response(Response::Nodes {
                    total: rlp.val_at::<u64>(1)?,
                    nodes,
                })
            }
            5 => {
                // TicketRequest
                if list_len != 2 {
                    debug!(
                        "Ticket Request has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let topic = {
                    let topic_bytes = rlp.val_at::<Vec<u8>>(1)?;
                    if topic_bytes.len() > 32 {
                        debug!("Ticket Request has a topic greater than 32 bytes");
                        return Err(DecoderError::RlpIsTooBig);
                    }
                    let mut topic = [0u8; 32];
                    topic[32 - topic_bytes.len()..].copy_from_slice(&topic_bytes);
                    topic
                };
                RpcType::Request(Request::Ticket { topic })
            }
            6 => {
                // TicketResponse
                if list_len != 3 {
                    debug!(
                        "Ticket Response has an invalid RLP list length. Expected 3, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let ticket = rlp.val_at::<Vec<u8>>(1)?;
                let wait_time = rlp.val_at::<u64>(2)?;
                RpcType::Response(Response::Ticket { ticket, wait_time })
            }
            7 => {
                // RegisterTopicRequest
                if list_len != 2 {
                    debug!("RegisterTopic Request has an invalid RLP list length. Expected 2, found {}", list_len);
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let ticket = rlp.val_at::<Vec<u8>>(1)?;
                RpcType::Request(Request::RegisterTopic { ticket })
            }
            8 => {
                // RegisterTopicResponse
                if list_len != 2 {
                    debug!("RegisterTopic Response has an invalid RLP list length. Expected 2, found {}", list_len);
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                RpcType::Response(Response::RegisterTopic {
                    registered: rlp.val_at::<bool>(1)?,
                })
            }
            9 => {
                // TopicQueryRequest
                if list_len != 2 {
                    debug!(
                        "TopicQuery Request has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let topic = {
                    let topic_bytes = rlp.val_at::<Vec<u8>>(1)?;
                    if topic_bytes.len() > 32 {
                        debug!("Ticket Request has a topic greater than 32 bytes");
                        return Err(DecoderError::RlpIsTooBig);
                    }
                    let mut topic = [0u8; 32];
                    topic[32 - topic_bytes.len()..].copy_from_slice(&topic_bytes);
                    topic
                };
                RpcType::Request(Request::TopicQuery { topic })
            }
            _ => {
                return Err(DecoderError::Custom("Unknown RPC message type"));
            }
        };

        Ok(ProtocolMessage { id, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::EnrBuilder;

    #[test]
    fn ref_test_encode_request_ping() {
        // reference input
        let id = 1;
        let enr_seq = 1;
        let body = RpcType::Request(Request::Ping { enr_seq });

        // expected hex output
        let expected_output = hex::decode("01c20101").unwrap();

        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_request_findnode() {
        // reference input
        let id = 1;
        let distance = 256;
        let body = RpcType::Request(Request::FindNode { distance });

        // expected hex output
        let expected_output = hex::decode("03c401820100").unwrap();

        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_request_ticket() {
        // reference input
        let id = 1;
        let hash_bytes =
            hex::decode("fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
                .unwrap();

        // expected hex output
        let expected_output =
            hex::decode("05e201a0fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
                .unwrap();

        let mut topic_hash = [0; 32];
        topic_hash.copy_from_slice(&hash_bytes);

        let body = RpcType::Request(Request::Ticket { topic: topic_hash });
        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_request_register_topic() {
        // reference input
        let id = 1;
        let ticket =
            hex::decode("fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
                .unwrap();

        // expected hex output
        let expected_output =
            hex::decode("07e201a0fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
                .unwrap();

        let body = RpcType::Request(Request::RegisterTopic { ticket });
        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_request_topic_query() {
        // reference input
        let id = 1;
        let hash_bytes =
            hex::decode("fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
                .unwrap();

        // expected hex output
        let expected_output =
            hex::decode("09e201a0fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736")
                .unwrap();

        let mut topic_hash = [0; 32];
        topic_hash.copy_from_slice(&hash_bytes);

        let body = RpcType::Request(Request::TopicQuery { topic: topic_hash });
        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_ping() {
        // reference input
        let id = 1;
        let enr_seq = 1;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let port = 5000;
        let body = RpcType::Response(Response::Ping { enr_seq, ip, port });

        // expected hex output
        let expected_output = hex::decode("02ca0101847f000001821388").unwrap();

        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes_empty() {
        // reference input
        let id = 1;
        let total = 1;

        let body = RpcType::Response(Response::Nodes {
            total,
            nodes: vec![],
        });
        // expected hex output
        let expected_output = hex::decode("04c30101c0").unwrap();
        let protocol_msg = ProtocolMessage { id, body };
        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes() {
        // reference input
        let id = 1;
        let total = 1;
        // ENR needs to be constructed from a keypair
        let key: CombinedKey = secp256k1::SecretKey::parse_slice(
            &hex::decode("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
                .unwrap(),
        )
        .unwrap()
        .into();

        let enr = EnrBuilder::new("v4").build(&key).unwrap();
        let body = RpcType::Response(Response::Nodes {
            total,
            nodes: vec![enr],
        });
        // expected hex output
        let expected_output = hex::decode("04f87b0101f877f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();

        let protocol_msg = ProtocolMessage { id, body };
        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes_multiple() {
        // reference input
        let id = 1;
        let total = 1;
        let enr = "enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr<CombinedKey>>().unwrap();

        let enr2 = "enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU".parse::<Enr<CombinedKey>>().unwrap();

        let body = RpcType::Response(Response::Nodes {
            total,
            nodes: vec![enr, enr2],
        });

        // expected hex output
        let expected_output = hex::decode("04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235").unwrap();

        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_decode_response_nodes_multiple() {
        let input = hex::decode("04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235").unwrap();

        let expected_enr1 = "enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr<CombinedKey>>().unwrap();
        let expected_enr2 = "enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU".parse::<Enr<CombinedKey>>().unwrap();

        let decoded = ProtocolMessage::decode(input).unwrap();

        match decoded.body {
            RpcType::Response(Response::Nodes { total, nodes }) => {
                assert_eq!(total, 1);
                assert_eq!(nodes[0], expected_enr1);
                assert_eq!(nodes[1], expected_enr2);
            }
            _ => panic!("Invalid decoding"),
        }
    }

    #[test]
    fn ref_test_encode_response_ticket() {
        // reference input
        let id = 1;
        let ticket = [0; 32].to_vec(); // all 0's
        let wait_time = 5;
        let body = RpcType::Response(Response::Ticket { ticket, wait_time });

        // expected hex output
        let expected_output = hex::decode(
            "06e301a0000000000000000000000000000000000000000000000000000000000000000005",
        )
        .unwrap();

        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_register_topic() {
        // reference input
        let id = 1;
        let registered = true;
        let body = RpcType::Response(Response::RegisterTopic { registered });

        // expected hex output
        let expected_output = hex::decode("08c20101").unwrap();

        let protocol_msg = ProtocolMessage { id, body };

        assert_eq!(protocol_msg.encode(), expected_output);
    }

    #[test]
    fn encode_decode_ping_request() {
        let request = ProtocolMessage {
            id: 10,
            body: RpcType::Request(Request::Ping { enr_seq: 15 }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ping_response() {
        let request = ProtocolMessage {
            id: 10,
            body: RpcType::Response(Response::Ping {
                enr_seq: 15,
                ip: "127.0.0.1".parse().unwrap(),
                port: 80,
            }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_find_node_request() {
        let request = ProtocolMessage {
            id: 10,
            body: RpcType::Request(Request::FindNode { distance: 1337 }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_nodes_response() {
        let key = CombinedKey::generate_secp256k1();
        let enr1 = EnrBuilder::new("v4")
            .ip("127.0.0.1".parse().unwrap())
            .udp(500)
            .build(&key)
            .unwrap();
        let enr2 = EnrBuilder::new("v4")
            .ip("10.0.0.1".parse().unwrap())
            .tcp(8080)
            .build(&key)
            .unwrap();
        let enr3 = EnrBuilder::new("v4")
            .ip("10.4.5.6".parse().unwrap())
            .build(&key)
            .unwrap();

        let enr_list = vec![enr1, enr2, enr3];
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Response(Response::Nodes {
                total: 1,
                nodes: enr_list,
            }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_request() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Request(Request::Ticket { topic: [17u8; 32] }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_response() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Response(Response::Ticket {
                ticket: vec![1, 2, 3, 4, 5],
                wait_time: 5,
            }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_request() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Request(Request::RegisterTopic {
                ticket: vec![1, 2, 3, 4, 5],
            }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_response() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Response(Response::RegisterTopic { registered: true }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_topic_query_request() {
        let request = ProtocolMessage {
            id: 0,
            body: RpcType::Request(Request::TopicQuery { topic: [17u8; 32] }),
        };

        let encoded = request.clone().encode();
        let decoded = ProtocolMessage::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }
}
