use enr::{CombinedKey, Enr};
use log::{debug, warn};
use rlp::{DecoderError, RlpStream};
use std::net::IpAddr;

type TopicHash = [u8; 32];

/// Wrapping type for requests.
pub type RequestId = u64;

#[derive(Debug, Clone, PartialEq)]
/// A combined type representing requests and responses.
pub enum Message {
    /// A request, which contains its [`RequestId`].
    Request(Request),
    /// A Response, which contains the [`RequestId`] of its associated request.
    Response(Response),
}

#[derive(Debug, Clone, PartialEq)]
/// A request sent between nodes.
pub struct Request {
    /// The [`RequestId`] of the request.
    pub id: RequestId,
    /// The body of the request.
    pub body: RequestBody,
}

#[derive(Debug, Clone, PartialEq)]
/// A response sent in response to a [`Request`]
pub struct Response {
    /// The [`RequestId`] of the request that triggered this response.
    pub id: RequestId,
    /// The body of this response.
    pub body: ResponseBody,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestBody {
    /// A PING request.
    Ping {
        /// Our current ENR sequence number.
        enr_seq: u64,
    },
    /// A FINDNODE request.
    FindNode {
        /// The distance(s) of peers we expect to be returned in the response.
        distances: Vec<u64>,
    },
    /// A TICKET request.
    Ticket { topic: TopicHash },
    /// A REGISTERTOPIC request.
    RegisterTopic { ticket: Vec<u8> },
    /// A TOPICQUERY request.
    TopicQuery { topic: TopicHash },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResponseBody {
    /// A PONG response.
    Ping {
        /// The current ENR sequence number of the responder.
        enr_seq: u64,
        /// Our external IP address as observed by the responder.
        ip: IpAddr,
        /// Our external UDP port as observed by the responder.
        port: u16,
    },
    /// A NODES response.
    Nodes {
        /// The total number of responses that make up this response.
        total: u64,
        /// A list of ENR's returned by the responder.
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

impl Request {
    pub fn msg_type(&self) -> u8 {
        match self.body {
            RequestBody::Ping { .. } => 1,
            RequestBody::FindNode { .. } => 3,
            RequestBody::Ticket { .. } => 5,
            RequestBody::RegisterTopic { .. } => 7,
            RequestBody::TopicQuery { .. } => 9,
        }
    }

    /// Encodes a Message to RLP-encoded bytes.
    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10);
        let msg_type = self.msg_type();
        buf.push(msg_type);
        let id = &self.id;
        match self.body {
            RequestBody::Ping { enr_seq } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(id);
                s.append(&enr_seq);
                buf.extend_from_slice(&s.drain());
                buf
            }
            RequestBody::FindNode { distances } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(id);
                s.begin_list(distances.len());
                for distance in distances {
                    s.append(&distance);
                }
                buf.extend_from_slice(&s.drain());
                buf
            }
            RequestBody::Ticket { topic } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(id);
                s.append(&topic.to_vec());
                buf.extend_from_slice(&s.drain());
                buf
            }
            RequestBody::RegisterTopic { ticket } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(id);
                s.append(&ticket.to_vec());
                buf.extend_from_slice(&s.drain());
                buf
            }
            RequestBody::TopicQuery { topic } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(id);
                s.append(&topic.to_vec());
                buf.extend_from_slice(&s.drain());
                buf
            }
        }
    }
}

impl Response {
    pub fn msg_type(&self) -> u8 {
        match &self.body {
            ResponseBody::Ping { .. } => 2,
            ResponseBody::Nodes { .. } => 4,
            ResponseBody::Ticket { .. } => 6,
            ResponseBody::RegisterTopic { .. } => 8,
        }
    }

    /// Determines if the response is a valid response to the given request.
    pub fn match_request(&self, req: &RequestBody) -> bool {
        match self.body {
            ResponseBody::Ping { .. } => {
                if let RequestBody::Ping { .. } = req {
                    true
                } else {
                    false
                }
            }
            ResponseBody::Nodes { .. } => match req {
                RequestBody::FindNode { .. } => true,
                RequestBody::TopicQuery { .. } => true,
                _ => false,
            },
            ResponseBody::Ticket { .. } => {
                if let RequestBody::Ticket { .. } = req {
                    true
                } else {
                    false
                }
            }
            ResponseBody::RegisterTopic { .. } => {
                if let RequestBody::TopicQuery { .. } = req {
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Encodes a Message to RLP-encoded bytes.
    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10);
        let msg_type = self.msg_type();
        buf.push(msg_type);
        let id = &self.id;
        match self.body {
            ResponseBody::Ping { enr_seq, ip, port } => {
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
            ResponseBody::Nodes { total, nodes } => {
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
            ResponseBody::Ticket { ticket, wait_time } => {
                let mut s = RlpStream::new();
                s.begin_list(3);
                s.append(id);
                s.append(&ticket.to_vec());
                s.append(&wait_time);
                buf.extend_from_slice(&s.drain());
                buf
            }
            ResponseBody::RegisterTopic { registered } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(id);
                s.append(&registered);
                buf.extend_from_slice(&s.drain());
                buf
            }
        }
    }
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Request(request) => write!(f, "{}", request),
            Message::Response(response) => write!(f, "{}", response),
        }
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Response: id: {}: {}", self.id, self.body)
    }
}

impl std::fmt::Display for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseBody::Ping { enr_seq, ip, port } => write!(
                f,
                "PONG: Enr-seq: {}, Ip: {:?},  Port: {}",
                enr_seq, ip, port
            ),
            ResponseBody::Nodes { total, nodes } => {
                let _ = write!(f, "NODES: total: {}, Nodes: [", total);
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
            ResponseBody::Ticket { ticket, wait_time } => {
                write!(f, "TICKET: Ticket: {:?}, Wait time: {}", ticket, wait_time)
            }
            ResponseBody::RegisterTopic { registered } => {
                write!(f, "REGTOPIC: Registered: {}", registered)
            }
        }
    }
}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Request: id: {}: {}", self.id, self.body)
    }
}

impl std::fmt::Display for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestBody::Ping { enr_seq } => write!(f, "PING: enr_seq: {}", enr_seq),
            RequestBody::FindNode { distances } => {
                write!(f, "FINDNODE Request: distance: {:?}", distances)
            }
            RequestBody::Ticket { topic } => write!(f, "TICKET: topic: {:?}", topic),
            RequestBody::TopicQuery { topic } => write!(f, "TOPICQUERY: topic: {:?}", topic),
            RequestBody::RegisterTopic { ticket } => {
                write!(f, "TOPICQUERY: ticket: {}", hex::encode(ticket))
            }
        }
    }
}
#[allow(dead_code)]
impl Message {
    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Request(request) => request.encode(),
            Self::Response(response) => response.encode(),
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

        let message = match msg_type {
            1 => {
                // PingRequest
                if list_len != 2 {
                    debug!(
                        "Ping Request has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                Message::Request(Request {
                    id,
                    body: RequestBody::Ping {
                        enr_seq: rlp.val_at::<u64>(1)?,
                    },
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
                Message::Response(Response {
                    id,
                    body: ResponseBody::Ping {
                        enr_seq: rlp.val_at::<u64>(1)?,
                        ip,
                        port,
                    },
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
                let distances = rlp.list_at::<u64>(1)?;

                if distances.len() > 5 {
                    warn!(
                        "Rejected FindNode request asking for too many buckets {}, maximum 5",
                        distances.len()
                    );
                    return Err(DecoderError::Custom("FINDNODE request too large"));
                }
                Message::Request(Request {
                    id,
                    body: RequestBody::FindNode { distances },
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
                Message::Response(Response {
                    id,
                    body: ResponseBody::Nodes {
                        total: rlp.val_at::<u64>(1)?,
                        nodes,
                    },
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
                Message::Request(Request {
                    id,
                    body: RequestBody::Ticket { topic },
                })
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
                Message::Response(Response {
                    id,
                    body: ResponseBody::Ticket { ticket, wait_time },
                })
            }
            7 => {
                // RegisterTopicRequest
                if list_len != 2 {
                    debug!("RegisterTopic Request has an invalid RLP list length. Expected 2, found {}", list_len);
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let ticket = rlp.val_at::<Vec<u8>>(1)?;
                Message::Request(Request {
                    id,
                    body: RequestBody::RegisterTopic { ticket },
                })
            }
            8 => {
                // RegisterTopicResponse
                if list_len != 2 {
                    debug!("RegisterTopic Response has an invalid RLP list length. Expected 2, found {}", list_len);
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                Message::Response(Response {
                    id,
                    body: ResponseBody::RegisterTopic {
                        registered: rlp.val_at::<bool>(1)?,
                    },
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
                Message::Request(Request {
                    id,
                    body: RequestBody::TopicQuery { topic },
                })
            }
            _ => {
                return Err(DecoderError::Custom("Unknown RPC message type"));
            }
        };

        Ok(message)
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
        let message = Message::Request(Request {
            id,
            body: RequestBody::Ping { enr_seq },
        });

        // expected hex output
        let expected_output = hex::decode("01c20101").unwrap();

        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_request_findnode() {
        // reference input
        let id = 1;
        let distances = vec![256];
        let message = Message::Request(Request {
            id,
            body: RequestBody::FindNode { distances },
        });

        // expected hex output
        let expected_output = hex::decode("03c401820100").unwrap();

        assert_eq!(message.encode(), expected_output);
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

        let message = Message::Request(Request {
            id,
            body: RequestBody::Ticket { topic: topic_hash },
        });
        assert_eq!(message.encode(), expected_output);
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

        let message = Message::Request(Request {
            id,
            body: RequestBody::RegisterTopic { ticket },
        });
        assert_eq!(message.encode(), expected_output);
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

        let message = Message::Request(Request {
            id,
            body: RequestBody::TopicQuery { topic: topic_hash },
        });
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_ping() {
        // reference input
        let id = 1;
        let enr_seq = 1;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let port = 5000;
        let message = Message::Response(Response {
            id,
            body: ResponseBody::Ping { enr_seq, ip, port },
        });

        // expected hex output
        let expected_output = hex::decode("02ca0101847f000001821388").unwrap();

        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes_empty() {
        // reference input
        let id = 1;
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
        // expected hex output
        let expected_output = hex::decode("04f87b0101f877f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();

        let message = Message::Response(Response {
            id,
            body: ResponseBody::Nodes {
                total,
                nodes: vec![enr],
            },
        });
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes_multiple() {
        // reference input
        let id = 1;
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
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_decode_response_nodes_multiple() {
        let input = hex::decode("04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235").unwrap();

        let expected_enr1 = "enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr<CombinedKey>>().unwrap();
        let expected_enr2 = "enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU".parse::<Enr<CombinedKey>>().unwrap();

        let decoded = Message::decode(input).unwrap();

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
    fn ref_test_encode_response_ticket() {
        // reference input
        let id = 1;
        let ticket = [0; 32].to_vec(); // all 0's
        let wait_time = 5;

        // expected hex output
        let expected_output = hex::decode(
            "06e301a0000000000000000000000000000000000000000000000000000000000000000005",
        )
        .unwrap();

        let message = Message::Response(Response {
            id,
            body: ResponseBody::Ticket { ticket, wait_time },
        });
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn ref_test_encode_response_register_topic() {
        // reference input
        let id = 1;
        let registered = true;

        // expected hex output
        let expected_output = hex::decode("08c20101").unwrap();
        let message = Message::Response(Response {
            id,
            body: ResponseBody::RegisterTopic { registered },
        });
        assert_eq!(message.encode(), expected_output);
    }

    #[test]
    fn encode_decode_ping_request() {
        let request = Message::Request(Request {
            id: 1,
            body: RequestBody::Ping { enr_seq: 15 },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ping_response() {
        let request = Message::Response(Response {
            id: 1,
            body: ResponseBody::Ping {
                enr_seq: 15,
                ip: "127.0.0.1".parse().unwrap(),
                port: 80,
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_find_node_request() {
        let request = Message::Request(Request {
            id: 1,
            body: RequestBody::FindNode {
                distances: vec![1337],
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

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
        let request = Message::Response(Response {
            id: 1,
            body: ResponseBody::Nodes {
                total: 1,
                nodes: enr_list,
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_request() {
        let request = Message::Request(Request {
            id: 1,
            body: RequestBody::Ticket { topic: [17u8; 32] },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_response() {
        let request = Message::Response(Response {
            id: 0,
            body: ResponseBody::Ticket {
                ticket: vec![1, 2, 3, 4, 5],
                wait_time: 5,
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_request() {
        let request = Message::Request(Request {
            id: 1,
            body: RequestBody::RegisterTopic {
                ticket: vec![1, 2, 3, 4, 5],
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_response() {
        let request = Message::Response(Response {
            id: 0,
            body: ResponseBody::RegisterTopic { registered: true },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_topic_query_request() {
        let request = Message::Request(Request {
            id: 1,
            body: RequestBody::TopicQuery { topic: [17u8; 32] },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(encoded).unwrap();

        assert_eq!(request, decoded);
    }
}
