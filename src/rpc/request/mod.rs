use super::{FINDNODE_MSG_TYPE, PING_MSG_TYPE, TALKREQ_MSG_TYPE};
use crate::impl_from_tuple_struct_unwrap;
use parse_display_derive::Display;
use rlp::{DecoderError, Rlp, RlpStream};
use tracing::{debug, warn};

mod request_body;

pub use request_body::RequestBody;

/// A request sent between nodes.
#[derive(Debug, Clone, PartialEq, Eq, Display)]
#[display("Request: id: {id}: {body}")]
pub struct Request {
    /// The [`RequestId`] of the request.
    pub id: RequestId,
    /// The body of the request.
    pub body: RequestBody,
}

impl Request {
    pub fn msg_type(&self) -> u8 {
        match self.body {
            RequestBody::Ping { .. } => 1,
            RequestBody::FindNode { .. } => 3,
            RequestBody::TalkReq { .. } => 5,
        }
    }

    /// Encodes a request message to RLP-encoded bytes.
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
            RequestBody::TalkReq { protocol, request } => {
                let mut s = RlpStream::new();
                s.begin_list(3);
                s.append(&id.as_bytes());
                s.append(&protocol);
                s.append(&request);
                buf.extend_from_slice(&s.out());
                buf
            }
        }
    }

    /// Decodes RLP-encoded bytes into a request message.
    pub fn decode(msg_type: u8, rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        let list_len = rlp.item_count()?;
        let id = RequestId::decode(rlp.val_at::<Vec<u8>>(0)?)?;
        let message = match msg_type {
            PING_MSG_TYPE => {
                // Ping Request
                if list_len != 2 {
                    debug!(
                        "Ping Request has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                Self {
                    id,
                    body: RequestBody::Ping {
                        enr_seq: rlp.val_at::<u64>(1)?,
                    },
                }
            }
            FINDNODE_MSG_TYPE => {
                // FindNode Request
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

                Self {
                    id,
                    body: RequestBody::FindNode { distances },
                }
            }
            TALKREQ_MSG_TYPE => {
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
                Self {
                    id,
                    body: RequestBody::TalkReq { protocol, request },
                }
            }
            _ => return Err(DecoderError::Custom("Unknown RPC request message type")),
        };
        Ok(message)
    }
}

/// Type to manage the request IDs.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct RequestId(pub Vec<u8>);

impl_from_tuple_struct_unwrap!(, RequestId, Vec<u8>);

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

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
