use super::{MessageType, Payload, RequestBody, RequestId};
use crate::Enr;
use derive_more::Display;
use rlp::{DecoderError, Rlp, RlpStream};
use std::{
    convert::TryInto,
    net::{IpAddr, Ipv6Addr},
};
use tracing::debug;

/// A response sent in response to a [`super::Request`]
#[derive(Debug, Clone, PartialEq, Eq, Display)]
#[display(fmt = "Response: id: {id}: {body}")]
pub struct Response {
    /// The [`RequestId`] of the request that triggered this response.
    pub id: RequestId,
    /// The body of this response.
    pub body: ResponseBody,
}

impl Payload for Response {
    /// Matches a response type to its message type id.
    fn msg_type(&self) -> u8 {
        match &self.body {
            ResponseBody::Pong { .. } => MessageType::Pong as u8,
            ResponseBody::Nodes { .. } => MessageType::Nodes as u8,
            ResponseBody::TalkResp { .. } => MessageType::TalkResp as u8,
        }
    }

    /// Encodes a response message to RLP-encoded bytes.
    fn encode(self) -> Vec<u8> {
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
            ResponseBody::TalkResp { response } => {
                let mut s = RlpStream::new();
                s.begin_list(2);
                s.append(&id.as_bytes());
                s.append(&response);
                buf.extend_from_slice(&s.out());
                buf
            }
        }
    }

    /// Decodes RLP-encoded bytes into a response message.
    fn decode(msg_type: u8, rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        let list_len = rlp.item_count()?;
        let id = RequestId::decode(rlp.val_at::<Vec<u8>>(0)?)?;
        let response = match msg_type.try_into()? {
            MessageType::Pong => {
                // Pong Response
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
                        if ipv6.is_loopback() {
                            // Checking if loopback address since IPv6Addr::to_ipv4 returns
                            // IPv4 address for IPv6 loopback address.
                            IpAddr::V6(ipv6)
                        } else if let Some(ipv4) = ipv6.to_ipv4() {
                            // If the ipv6 is ipv4 compatible/mapped, simply return the ipv4.
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
                Self {
                    id,
                    body: ResponseBody::Pong {
                        enr_seq: rlp.val_at::<u64>(1)?,
                        ip,
                        port,
                    },
                }
            }
            MessageType::Nodes => {
                // Nodes Response
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
                        enr_list_rlp.as_list::<Enr>()?
                    }
                };
                Self {
                    id,
                    body: ResponseBody::Nodes {
                        total: rlp.val_at::<u64>(1)?,
                        nodes,
                    },
                }
            }
            MessageType::TalkResp => {
                // Talk Response
                if list_len != 2 {
                    debug!(
                        "Talk Response has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let response = rlp.val_at::<Vec<u8>>(1)?;
                Self {
                    id,
                    body: ResponseBody::TalkResp { response },
                }
            }
            _ => unreachable!("Implementation does not adhere to wire protocol"),
        };
        Ok(response)
    }
}

impl Response {
    /// Determines if the response is a valid response to the given request.
    pub fn match_request(&self, req: &RequestBody) -> bool {
        match self.body {
            ResponseBody::Pong { .. } => matches!(req, RequestBody::Ping { .. }),
            ResponseBody::Nodes { .. } => {
                matches!(req, RequestBody::FindNode { .. })
            }
            ResponseBody::TalkResp { .. } => matches!(req, RequestBody::TalkReq { .. }),
        }
    }
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
        nodes: Vec<Enr>,
    },
    /// The TALK response.
    TalkResp {
        /// The response for the talk.
        response: Vec<u8>,
    },
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
            ResponseBody::TalkResp { response } => {
                write!(f, "Response: Response {}", hex::encode(response))
            }
        }
    }
}
