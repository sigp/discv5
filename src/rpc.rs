use enr::{CombinedKey, Enr};
use rlp::{DecoderError, RlpStream};
use std::net::{IpAddr, Ipv6Addr};
use tracing::{debug, warn};

type TopicHash = [u8; 32];

/// Type to manage the request IDs.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct RequestId(pub Vec<u8>);

impl From<RequestId> for Vec<u8> {
    fn from(id: RequestId) -> Self {
        id.0
    }
}

impl RequestId {
    /// Decodes the ID from a raw bytes.
    pub fn decode(data: Vec<u8>) -> Result<Self, DecoderError> {
        if data.len() > 8 {
            return Err(DecoderError::Custom("Invalid ID length"));
        }
        Ok(RequestId(data))
    }

    pub fn random() -> Self {
        let rand: u64 = rand::random();
        RequestId(rand.to_be_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A combined type representing requests and responses.
pub enum Message {
    /// A request, which contains its [`RequestId`].
    Request(Request),
    /// A Response, which contains the [`RequestId`] of its associated request.
    Response(Response),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A request sent between nodes.
pub struct Request {
    /// The [`RequestId`] of the request.
    pub id: RequestId,
    /// The body of the request.
    pub body: RequestBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A response sent in response to a [`Request`]
pub struct Response {
    /// The [`RequestId`] of the request that triggered this response.
    pub id: RequestId,
    /// The body of this response.
    pub body: ResponseBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A Talk request.
    Talk {
        /// The protocol requesting.
        protocol: Vec<u8>,
        /// The request.
        request: Vec<u8>,
    },
    /// A REGISTERTOPIC request.
    RegisterTopic {
        topic: Vec<u8>,
        enr: crate::Enr,
        ticket: Vec<u8>,
    },
    /// A TOPICQUERY request.
    TopicQuery { topic: TopicHash },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseBody {
    /// A PONG response.
    Pong {
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
    /// The TALK response.
    Talk {
        /// The response for the talk.
        response: Vec<u8>,
    },
    Ticket {
        ticket: Vec<u8>,
        wait_time: u64,
    },
    RegisterConfirmation {
        topic: Vec<u8>,
    },
}

impl Request {
    pub fn msg_type(&self) -> u8 {
        match self.body {
            RequestBody::Ping { .. } => 1,
            RequestBody::FindNode { .. } => 3,
            RequestBody::Talk { .. } => 5,
            RequestBody::RegisterTopic { .. } => 7,
            RequestBody::TopicQuery { .. } => 10,
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
                s.append(&id.as_bytes());
                s.append(&enr_seq);
                buf.extend_from_slice(&s.out());
                buf
            }
            RequestBody::FindNode { distances } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(&id.as_bytes());
                s.begin_list(distances.len());
                for distance in distances {
                    s.append(&distance);
                }
                buf.extend_from_slice(&s.out());
                buf
            }
            RequestBody::Talk { protocol, request } => {
                let mut s = RlpStream::new();
                s.begin_list(3);
                s.append(&id.as_bytes());
                s.append(&protocol);
                s.append(&request);
                buf.extend_from_slice(&s.out());
                buf
            }
            RequestBody::RegisterTopic { topic, enr, ticket } => {
                let mut s = RlpStream::new();
                s.begin_list(4);
                s.append(&id.as_bytes());
                s.append(&topic);
                s.append(&enr);
                s.append(&ticket);
                buf.extend_from_slice(&s.out());
                buf
            }
            RequestBody::TopicQuery { topic } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(&id.as_bytes());
                s.append(&(&topic as &[u8]));
                buf.extend_from_slice(&s.out());
                buf
            }
        }
    }
}

impl Response {
    pub fn msg_type(&self) -> u8 {
        match &self.body {
            ResponseBody::Pong { .. } => 2,
            ResponseBody::Nodes { .. } => 4,
            ResponseBody::Talk { .. } => 6,
            ResponseBody::Ticket { .. } => 8,
            ResponseBody::RegisterConfirmation { .. } => 9,
        }
    }

    /// Determines if the response is a valid response to the given request.
    pub fn match_request(&self, req: &RequestBody) -> bool {
        match self.body {
            ResponseBody::Pong { .. } => matches!(req, RequestBody::Ping { .. }),
            ResponseBody::Nodes { .. } => {
                matches!(
                    req,
                    RequestBody::FindNode { .. } | RequestBody::TopicQuery { .. }
                )
            }
            ResponseBody::Talk { .. } => matches!(req, RequestBody::Talk { .. }),
            ResponseBody::Ticket { .. } => matches!(req, RequestBody::RegisterTopic { .. }),
            ResponseBody::RegisterConfirmation { .. } => {
                matches!(req, RequestBody::RegisterTopic { .. })
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
            ResponseBody::Pong { enr_seq, ip, port } => {
                let mut s = RlpStream::new();
                s.begin_list(4);
                s.append(&id.as_bytes());
                s.append(&enr_seq);
                match ip {
                    IpAddr::V4(addr) => s.append(&(&addr.octets() as &[u8])),
                    IpAddr::V6(addr) => s.append(&(&addr.octets() as &[u8])),
                };
                s.append(&port);
                buf.extend_from_slice(&s.out());
                buf
            }
            ResponseBody::Nodes { total, nodes } => {
                let mut s = RlpStream::new();
                s.begin_list(3);
                s.append(&id.as_bytes());
                s.append(&total);

                if nodes.is_empty() {
                    s.begin_list(0);
                } else {
                    s.begin_list(nodes.len());
                    for node in nodes {
                        s.append(&node);
                    }
                }
                buf.extend_from_slice(&s.out());
                buf
            }
            ResponseBody::Talk { response } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(&id.as_bytes());
                s.append(&response);
                buf.extend_from_slice(&s.out());
                buf
            }
            ResponseBody::Ticket { ticket, wait_time } => {
                let mut s = RlpStream::new();
                s.begin_list(3);
                s.append(&id.as_bytes());
                s.append(&ticket);
                s.append(&wait_time);
                buf.extend_from_slice(&s.out());
                buf
            }
            ResponseBody::RegisterConfirmation { topic } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(&id.as_bytes());
                s.append(&topic);
                buf.extend_from_slice(&s.out());
                buf
            }
        }
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Request(request) => write!(f, "{request}"),
            Message::Response(response) => write!(f, "{response}"),
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
            ResponseBody::Pong { enr_seq, ip, port } => {
                write!(f, "PONG: Enr-seq: {enr_seq}, Ip: {ip:?},  Port: {port}")
            }
            ResponseBody::Nodes { total, nodes } => {
                write!(f, "NODES: total: {total}, Nodes: [")?;
                let mut first = true;
                for id in nodes {
                    if !first {
                        write!(f, ", {id}")?;
                    } else {
                        write!(f, "{id}")?;
                    }
                    first = false;
                }

                write!(f, "]")
            }
            ResponseBody::Talk { response } => {
                write!(f, "Response: Response {}", hex::encode(response))
            }
            ResponseBody::Ticket { ticket, wait_time } => {
                write!(f, "TICKET: Ticket: {ticket:?}, Wait time: {wait_time}")
            }
            ResponseBody::RegisterConfirmation { topic } => {
                write!(f, "REGTOPIC: Registered: {}", hex::encode(topic))
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
            RequestBody::Ping { enr_seq } => write!(f, "PING: enr_seq: {enr_seq}"),
            RequestBody::FindNode { distances } => {
                write!(f, "FINDNODE Request: distance: {distances:?}")
            }
            RequestBody::Talk { protocol, request } => write!(
                f,
                "TALK: protocol: {}, request: {}",
                hex::encode(protocol),
                hex::encode(request)
            ),
            RequestBody::TopicQuery { topic } => write!(f, "TOPICQUERY: topic: {topic:?}"),
            RequestBody::RegisterTopic { topic, enr, ticket } => write!(
                f,
                "RegisterTopic: topic: {}, enr: {}, ticket: {}",
                hex::encode(topic),
                enr.to_base64(),
                hex::encode(ticket)
            ),
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

    pub fn decode(data: &[u8]) -> Result<Self, DecoderError> {
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

        let id = RequestId::decode(rlp.val_at::<Vec<u8>>(0)?)?;

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
                        let ipv6 = Ipv6Addr::from(ip);
                        // If the ipv6 is ipv4 compatible/mapped, simply return the ipv4.
                        if let Some(ipv4) = ipv6.to_ipv4() {
                            IpAddr::V4(ipv4)
                        } else {
                            IpAddr::V6(ipv6)
                        }
                    }
                    _ => {
                        debug!("Ping Response has incorrect byte length for IP");
                        return Err(DecoderError::RlpIncorrectListLen);
                    }
                };
                let port = rlp.val_at::<u16>(3)?;
                Message::Response(Response {
                    id,
                    body: ResponseBody::Pong {
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

                for distance in distances.iter() {
                    if distance > &256u64 {
                        warn!(
                            "Rejected FindNode request asking for unknown distance {}, maximum 256",
                            distance
                        );
                        return Err(DecoderError::Custom("FINDNODE request distance invalid"));
                    }
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
                // Talk Request
                if list_len != 3 {
                    debug!(
                        "Talk Request has an invalid RLP list length. Expected 3, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let protocol = rlp.val_at::<Vec<u8>>(1)?;
                let request = rlp.val_at::<Vec<u8>>(2)?;
                Message::Request(Request {
                    id,
                    body: RequestBody::Talk { protocol, request },
                })
            }
            6 => {
                // Talk Response
                if list_len != 2 {
                    debug!(
                        "Talk Response has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let response = rlp.val_at::<Vec<u8>>(1)?;
                Message::Response(Response {
                    id,
                    body: ResponseBody::Talk { response },
                })
            }
            _ => {
                return Err(DecoderError::Custom("Unknown RPC message type"));
            } /*
               * All other RPC messages are currently not supported as per the 5.1 specification.

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
              */
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
    fn encode_decode_ticket_request() {
        let id = RequestId(vec![1]);
        let request = Message::Request(Request {
            id,
            body: RequestBody::Talk {
                protocol: vec![17u8; 32],
                request: vec![1, 2, 3],
            },
        });

        let encoded = request.clone().encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(request, decoded);
    }

    /*
     * These RPC messages are not in use yet
     *
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
    fn encode_decode_register_topic_request() {
        let request = Message::Request(Request {
            id: 1,
            body: RequestBody::RegisterTopic {
                topic: vec![1,2,3],
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

    */
}
