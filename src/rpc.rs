use crate::{advertisement::topic::TopicHash, Enr};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    Aes128Gcm,
};
use enr::NodeId;
use more_asserts::debug_unreachable;
use rlp::{DecoderError, Rlp, RlpStream};
use std::{
    net::{IpAddr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::{Duration, Instant};
use tracing::{debug, error, warn};

pub const FALSE_TICKET: &str = "TICKET_ENCRYPTED_BY_FOREIGN_KEY";

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RequestTicket {
    Empty,
    LocallyIssued(Ticket),
    RemotelyIssued(Vec<u8>),
}

impl RequestTicket {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut s = RlpStream::new();
        s.append(self);
        buf.extend_from_slice(&s.out());
        buf
    }

    pub fn decode(ticket: &[u8]) -> Result<Self, DecoderError> {
        let rlp = rlp::Rlp::new(ticket);
        let request_ticket = rlp.as_val::<RequestTicket>()?;
        Ok(request_ticket)
    }
}

impl rlp::Encodable for RequestTicket {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            RequestTicket::Empty => {
                s.append(&Vec::new());
            }
            RequestTicket::LocallyIssued(ticket) => {
                debug!("A locally issued ticket will never be sent in the form of a request hence the RequestTicket::LocallyIssued variant should not need to be encoded. This functionality should merely be invoked by tests.");
                s.append(ticket);
            }
            RequestTicket::RemotelyIssued(bytes) => {
                // A remotely issued ticket is encoded to return it to its issuer once its wait
                // time expires.
                s.append(bytes);
            }
        }
    }
}

impl rlp::Decodable for RequestTicket {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        // If a ticket is incoming in a REGTOPIC request, and we hence decode
        // the request, it should only be a ticket that was locally issued. A
        // remotely issued ticket RegtopicTicket::Remote will only be encoded
        // by this node to return it to its issuer.
        Ok(RequestTicket::LocallyIssued(rlp.as_val::<Ticket>()?))
    }
}

impl std::fmt::Display for RequestTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestTicket::Empty => {
                write!(f, "Empty")
            }
            RequestTicket::LocallyIssued(ticket) => {
                write!(f, "Locally issued ticket: {}", ticket)
            }
            RequestTicket::RemotelyIssued(bytes) => {
                write!(f, "Remotely issued ticket: {}", hex::encode(bytes))
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResponseTicket {
    LocallyIssued(Ticket),
    RemotelyIssued(Vec<u8>),
}

impl ResponseTicket {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut s = RlpStream::new();
        s.append(self);
        buf.extend_from_slice(&s.out());
        buf
    }

    pub fn decode(ticket: &[u8]) -> Result<Self, DecoderError> {
        let rlp = rlp::Rlp::new(ticket);
        let response_ticket = rlp.as_val::<ResponseTicket>()?;
        Ok(response_ticket)
    }
}

impl rlp::Encodable for ResponseTicket {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            ResponseTicket::LocallyIssued(ticket) => {
                s.append(ticket);
            }
            ResponseTicket::RemotelyIssued(bytes) => {
                debug!("A remotely issued ticket will never be returned to the issuer in the form of a response hence the ResponseTicket::RemotelyIssued variant should not need to be encoded. This functionality should merely be invoked by tests.");
                s.append(bytes);
            }
        }
    }
}

impl rlp::Decodable for ResponseTicket {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        // If a ticket is incoming in a TICKET response, and we hence decode
        // the response, it should only be a ticket that was remotely issued.
        // A locally issued ticket ResponseTicket::Local will only be encoded
        // by this node and sent to a given peer.
        Ok(ResponseTicket::RemotelyIssued(rlp.as_val::<Vec<u8>>()?))
    }
}

impl std::fmt::Display for ResponseTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseTicket::LocallyIssued(ticket) => {
                write!(f, "Locally issued ticket: {}", ticket)
            }
            ResponseTicket::RemotelyIssued(bytes) => {
                write!(f, "Remotely issued ticket: {}", hex::encode(bytes))
            }
        }
    }
}

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
    /// A TALKREQ request.
    Talk {
        /// The protocol requesting.
        protocol: Vec<u8>,
        /// The request.
        request: Vec<u8>,
    },
    /// A REGTOPIC request.
    RegisterTopic {
        /// The topic string we want to advertise at the node receiving this request.
        topic: String,
        // Current node record of sender.
        enr: Enr,
        // Ticket content of ticket from a previous registration attempt or empty.
        ticket: RequestTicket,
    },
    /// A TOPICQUERY request.
    TopicQuery {
        /// The hashed topic we want NODES response(s) for.
        topic: TopicHash,
    },
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
    /// A NODES response to a FINDNODE or TOPICQUERY request.
    Nodes {
        /// The total number of responses that make up this response.
        total: u64,
        /// A list of ENRs returned by the responder.
        nodes: Vec<Enr>,
    },
    /// The TALKRESP response.
    Talk {
        /// The response for the TALKREQ request.
        response: Vec<u8>,
    },
    /// The TICKET response.
    Ticket {
        /// The response to a REGTOPIC request.
        ticket: ResponseTicket,
        /// The time in seconds to wait before attempting to register again.
        wait_time: u64,
        /// The topic hash for which the opaque ticket is issued.
        topic: String,
    },
}

impl Request {
    pub fn msg_type(&self) -> u8 {
        match self.body {
            RequestBody::Ping { .. } => 1,
            RequestBody::FindNode { .. } => 3,
            RequestBody::Talk { .. } => 5,
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
                s.append(&topic);
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
        }
    }

    /// Encodes a Message to RLP-encoded bytes.
    pub fn encode(self, ticket_key: &[u8; 16]) -> Vec<u8> {
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
            ResponseBody::Ticket {
                ticket,
                wait_time,
                topic,
            } => {
                let aead = Aes128Gcm::new(GenericArray::from_slice(ticket_key));
                let payload = Payload {
                    msg: &ticket.encode(),
                    aad: b"",
                };
                if let Ok(encrypted_ticket) =
                    aead.encrypt(GenericArray::from_slice(&[1u8; 12]), payload)
                {
                    let mut s = RlpStream::new();
                    s.begin_list(4);
                    s.append(&id.as_bytes());
                    s.append(&encrypted_ticket);
                    s.append(&wait_time);
                    s.append(&topic);
                    buf.extend_from_slice(&s.out());
                }
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
            ResponseBody::Pong { enr_seq, ip, port } => write!(
                f,
                "PONG: enr-seq: {}, ip: {:?},  port: {}",
                enr_seq, ip, port
            ),
            ResponseBody::Nodes { total, nodes } => {
                write!(f, "NODES: total: {}, nodes: [", total)?;
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
            ResponseBody::Talk { response } => {
                write!(f, "TALK: response {}", hex::encode(response))
            }
            ResponseBody::Ticket {
                ticket,
                wait_time,
                topic,
            } => {
                write!(
                    f,
                    "TICKET: ticket: {}, wait time: {}, topic: {}",
                    ticket, wait_time, topic
                )
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
            RequestBody::Talk { protocol, request } => write!(
                f,
                "TALK: protocol: {}, request: {}",
                hex::encode(protocol),
                hex::encode(request)
            ),
            RequestBody::TopicQuery { topic } => write!(f, "TOPICQUERY: topic: {}", topic),
            RequestBody::RegisterTopic { topic, enr, ticket } => write!(
                f,
                "REGTOPIC: topic: {}, enr: {}, ticket: {}",
                topic,
                enr.to_base64(),
                ticket,
            ),
        }
    }
}
#[allow(dead_code)]
impl Message {
    pub fn encode(self, ticket_key: &[u8; 16]) -> Vec<u8> {
        match self {
            Self::Request(request) => request.encode(),
            Self::Response(response) => response.encode(ticket_key),
        }
    }

    pub fn decode(data: &[u8], ticket_key: &[u8; 16]) -> Result<Self, DecoderError> {
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
                // PongResponse
                if list_len != 4 {
                    debug!(
                        "Pong Response has an invalid RLP list length. Expected 4, found {}",
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
                        debug!("Pong Response has incorrect byte length for IP");
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

                if distances.len() > 10 {
                    warn!(
                        "Rejected FindNode request asking for too many buckets {}, maximum 10",
                        distances.len()
                    );
                    return Err(DecoderError::Custom("FINDNODE request too large"));
                }
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
                        enr_list_rlp.as_list::<Enr>()?
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
                // TalkRequest
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
                // TalkResponse
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
            7 => {
                // RegisterTopicRequest
                if list_len != 4 {
                    debug!("RegisterTopic request has an invalid RLP list length. Expected 4, found {}", list_len);
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let topic = rlp.val_at::<String>(1)?;
                let enr_rlp = rlp.at(2)?;
                let enr = enr_rlp.as_val::<Enr>()?;
                let ticket = rlp.val_at::<Vec<u8>>(3)?;

                let returned_ticket = {
                    let aead = Aes128Gcm::new(GenericArray::from_slice(ticket_key));
                    let payload = Payload {
                        msg: &ticket,
                        aad: b"",
                    };
                    if !ticket.is_empty() {
                        if let Ok(decrypted_ticket) = aead.decrypt(GenericArray::from_slice(&[1u8; 12]), payload).map_err(|e| debug!("Failed to decrypt ticket in REGTOPIC request. Ticket not issued by us. Error: {}", e)) {
                            if let Ok(decoded_ticket) = RequestTicket::decode(&decrypted_ticket).map_err(|e| {
                                debug!("Failed to decode ticket in REGTOPIC request. Error: {}", e)
                            }) {
                                decoded_ticket
                            } else {
                                debug_unreachable!("Encoding of ticket issued locally is faulty");
                                return Err(DecoderError::Custom("Faulty encoding of ticket"));
                            }
                        } else {
                            return Err(DecoderError::Custom(FALSE_TICKET));
                        }
                    } else {
                        RequestTicket::Empty
                    }
                };
                Message::Request(Request {
                    id,
                    body: RequestBody::RegisterTopic {
                        topic,
                        enr,
                        ticket: returned_ticket,
                    },
                })
            }
            8 => {
                // TicketResponse
                if list_len != 4 {
                    debug!(
                        "Ticket Response has an invalid RLP list length. Expected 4, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let ticket = rlp.val_at::<ResponseTicket>(1)?;
                let wait_time = rlp.val_at::<u64>(2)?;
                let topic = rlp.val_at::<String>(3)?;
                Message::Response(Response {
                    id,
                    body: ResponseBody::Ticket {
                        ticket,
                        wait_time,
                        topic,
                    },
                })
            }
            9 => {
                // TopicQueryRequest
                if list_len != 2 {
                    debug!(
                        "TopicQuery request has an invalid RLP list length. Expected 2, found {}",
                        list_len
                    );
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                let topic = {
                    let topic_bytes = rlp.val_at::<Vec<u8>>(1)?;
                    if topic_bytes.len() > 32 {
                        debug!("TopicQuery request has a topic greater than 32 bytes");
                        return Err(DecoderError::RlpIsTooBig);
                    }
                    let mut topic = [0u8; 32];
                    topic[32 - topic_bytes.len()..].copy_from_slice(&topic_bytes);
                    TopicHash::from_raw(topic)
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

/// A ticket object, outlined in the spec.
#[derive(Debug, Clone, Eq)]
pub struct Ticket {
    src_node_id: NodeId,
    src_ip: IpAddr,
    topic: TopicHash,
    req_time: Instant,
    wait_time: Duration,
    //cum_wait: Duration,
}

impl rlp::Encodable for Ticket {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5);
        s.append(&self.src_node_id.raw().to_vec());
        match self.src_ip {
            IpAddr::V4(addr) => s.append(&(addr.octets().to_vec())),
            IpAddr::V6(addr) => s.append(&(addr.octets().to_vec())),
        };
        s.append(&self.topic);
        if let Ok(time_since_unix) = SystemTime::now().duration_since(UNIX_EPOCH) {
            let time_since_req = self.req_time.elapsed();
            let time_stamp = time_since_unix - time_since_req;
            s.append(&time_stamp.as_secs().to_be_bytes().to_vec());
        }
        s.append(&self.wait_time.as_secs().to_be_bytes().to_vec());
        //s.append(&self.cum_wait.as_secs().to_be_bytes().to_vec());
    }
}

impl rlp::Decodable for Ticket {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        if !rlp.is_list() {
            debug!("Failed to decode ENR. Not an RLP list: {}", rlp);
            return Err(DecoderError::RlpExpectedToBeList);
        }

        if rlp.item_count() != Ok(5) {
            error!(
                "List has wrong item count, should be 5 but is {:?}",
                rlp.item_count()
            );
            return Err(DecoderError::Custom("List has wrong item count"));
        }

        let mut decoded_list: Vec<Rlp<'_>> = rlp.iter().collect();

        let src_node_id = {
            let data = decoded_list.remove(0).data()?;
            if data.len() != 32 {
                debug!("Ticket's src-node-id is not 32 bytes");
                return Err(DecoderError::RlpIsTooBig);
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(data);
            NodeId::new(&raw)
        };

        let src_ip = {
            let data = decoded_list.remove(0).data()?;
            match data.len() {
                4 => {
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(data);
                    IpAddr::from(ip)
                }
                16 => {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(data);
                    let ipv6 = Ipv6Addr::from(ip);
                    // If the ipv6 is ipv4 compatible/mapped, simply return the ipv4.
                    // Ipv6 for Discv5 is coming soon.
                    if let Some(ipv4) = ipv6.to_ipv4() {
                        IpAddr::V4(ipv4)
                    } else {
                        IpAddr::V6(ipv6)
                    }
                }
                _ => {
                    debug!("Ticket has incorrect byte length for src-ip");
                    return Err(DecoderError::RlpIncorrectListLen);
                }
            }
        };

        let topic = decoded_list.remove(0).as_val::<TopicHash>()?;

        let req_time = {
            if let Ok(time_since_unix) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let secs_data = decoded_list.remove(0).data()?;
                let mut secs_bytes = [0u8; 8];
                secs_bytes.copy_from_slice(secs_data);
                let secs = u64::from_be_bytes(secs_bytes);
                let req_time_since_unix = Duration::from_secs(secs);
                let time_since_req = time_since_unix - req_time_since_unix;
                if let Some(req_time) = Instant::now().checked_sub(time_since_req) {
                    req_time
                } else {
                    return Err(DecoderError::Custom(
                        "Could not compute ticket req-time instant",
                    ));
                }
            } else {
                return Err(DecoderError::Custom("SystemTime before UNIX EPOCH!"));
            }
        };

        let wait_time = {
            let secs_data = decoded_list.remove(0).data()?;
            let mut secs_bytes = [0u8; 8];
            secs_bytes.copy_from_slice(secs_data);
            let secs = u64::from_be_bytes(secs_bytes);
            Duration::from_secs(secs)
        };

        /*let cum_wait = {
            let secs_data = decoded_list.remove(0).data()?;
            let mut secs_bytes = [0u8; 8];
            secs_bytes.copy_from_slice(secs_data);
            let secs = u64::from_be_bytes(secs_bytes);
            Duration::from_secs(secs)
        };*/

        Ok(Self {
            src_node_id,
            src_ip,
            topic,
            req_time,
            wait_time,
            //cum_wait,
        })
    }
}

/// Per topic, one registration attempt per node is stored at once.
/// Tickets that overlap based on these fields are considered equal.
impl PartialEq for Ticket {
    fn eq(&self, other: &Self) -> bool {
        self.src_node_id == other.src_node_id
            && self.src_ip == other.src_ip
            && self.topic == other.topic
    }
}

impl Ticket {
    pub fn new(
        src_node_id: NodeId,
        src_ip: IpAddr,
        topic: TopicHash,
        req_time: Instant,
        wait_time: Duration,
        //cum_wait: Duration,
    ) -> Self {
        Ticket {
            src_node_id,
            src_ip,
            topic,
            req_time,
            wait_time,
            //cum_wait,
        }
    }

    pub fn topic(&self) -> TopicHash {
        self.topic
    }

    pub fn req_time(&self) -> Instant {
        self.req_time
    }

    pub fn wait_time(&self) -> Duration {
        self.wait_time
    }

    pub fn set_wait_time(&mut self, wait_time: Duration) {
        self.wait_time = wait_time;
    }

    /*pub fn cum_wait(&self) -> Duration {
        self.cum_wait
    }

    pub fn update_cum_wait(&mut self) {
        self.cum_wait = self.cum_wait + self.wait_time;
    }*/

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut s = RlpStream::new();
        s.append(self);
        buf.extend_from_slice(&s.out());
        buf
    }

    pub fn decode(ticket: &[u8]) -> Result<Option<Self>, DecoderError> {
        if !ticket.is_empty() {
            let rlp = rlp::Rlp::new(ticket);
            let ticket = rlp.as_val::<Ticket>()?;
            return Ok(Some(ticket));
        }
        Ok(None)
    }
}

impl std::fmt::Display for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ticket: src node id: {}, src ip: {}, topic: {}, req time: {:?}, wait time: {}",
            self.src_node_id,
            self.src_ip,
            self.topic,
            self.req_time,
            self.wait_time.as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        aead::{generic_array::GenericArray, Aead, NewAead, Payload},
        Aes128Gcm,
    };
    use enr::EnrBuilder;

    #[test]
    fn ref_test_encode_request_ping() {
        let ticket_key: [u8; 16] = rand::random();

        // reference input
        let id = RequestId(vec![1]);
        let enr_seq = 1;
        let message = Message::Request(Request {
            id,
            body: RequestBody::Ping { enr_seq },
        });

        // expected hex output
        let expected_output = hex::decode("01c20101").unwrap();

        dbg!(hex::encode(message.clone().encode(&ticket_key)));
        assert_eq!(message.encode(&ticket_key), expected_output);
    }

    #[test]
    fn ref_test_encode_request_findnode() {
        let ticket_key: [u8; 16] = rand::random();

        // reference input
        let id = RequestId(vec![1]);
        let distances = vec![256];
        let message = Message::Request(Request {
            id,
            body: RequestBody::FindNode { distances },
        });

        // expected hex output
        let expected_output = hex::decode("03c501c3820100").unwrap();
        dbg!(hex::encode(message.clone().encode(&ticket_key)));

        assert_eq!(message.encode(&ticket_key), expected_output);
    }

    #[test]
    fn ref_test_encode_response_ping() {
        let ticket_key: [u8; 16] = rand::random();

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

        dbg!(hex::encode(message.clone().encode(&ticket_key)));
        assert_eq!(message.encode(&ticket_key), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes_empty() {
        let ticket_key: [u8; 16] = rand::random();

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
        assert_eq!(message.encode(&ticket_key), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes() {
        let ticket_key: [u8; 16] = rand::random();

        // reference input
        let id = RequestId(vec![1]);
        let total = 1;

        let enr = "-HW4QCjfjuCfSmIJHxqLYfGKrSz-Pq3G81DVJwd_muvFYJiIOkf0bGtJu7kZVCOPnhSTMneyvR4MRbF3G5TNB4wy2ssBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr>().unwrap();
        // expected hex output
        let expected_output = hex::decode("04f87b0101f877f875b84028df8ee09f4a62091f1a8b61f18aad2cfe3eadc6f350d527077f9aebc56098883a47f46c6b49bbb91954238f9e14933277b2bd1e0c45b1771b94cd078c32dacb0182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();

        let message = Message::Response(Response {
            id,
            body: ResponseBody::Nodes {
                total,
                nodes: vec![enr],
            },
        });
        dbg!(hex::encode(message.clone().encode(&ticket_key)));
        assert_eq!(message.encode(&ticket_key), expected_output);
    }

    #[test]
    fn ref_test_encode_response_nodes_multiple() {
        let ticket_key: [u8; 16] = rand::random();

        // reference input
        let id = RequestId(vec![1]);
        let total = 1;
        let enr = "enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr>().unwrap();

        let enr2 = "enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU".parse::<Enr>().unwrap();

        // expected hex output
        let expected_output = hex::decode("04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235").unwrap();

        let message = Message::Response(Response {
            id,
            body: ResponseBody::Nodes {
                total,
                nodes: vec![enr, enr2],
            },
        });
        dbg!(hex::encode(message.clone().encode(&ticket_key)));
        assert_eq!(message.encode(&ticket_key), expected_output);
    }

    #[test]
    fn ref_decode_response_nodes_multiple() {
        let ticket_key: [u8; 16] = rand::random();
        let input = hex::decode("04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235").unwrap();

        let expected_enr1 = "enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg".parse::<Enr>().unwrap();
        let expected_enr2 = "enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU".parse::<Enr>().unwrap();

        let decoded = Message::decode(&input, &ticket_key).unwrap();

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
        let ticket_key: [u8; 16] = rand::random();
        let id = RequestId(vec![1]);
        let request = Message::Request(Request {
            id,
            body: RequestBody::Ping { enr_seq: 15 },
        });

        let encoded = request.clone().encode(&ticket_key);
        let decoded = Message::decode(&encoded, &ticket_key).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ping_response() {
        let ticket_key: [u8; 16] = rand::random();
        let id = RequestId(vec![1]);
        let request = Message::Response(Response {
            id,
            body: ResponseBody::Pong {
                enr_seq: 15,
                ip: "127.0.0.1".parse().unwrap(),
                port: 80,
            },
        });

        let encoded = request.clone().encode(&ticket_key);
        let decoded = Message::decode(&encoded, &ticket_key).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_find_node_request() {
        let ticket_key: [u8; 16] = rand::random();
        let id = RequestId(vec![1]);
        let request = Message::Request(Request {
            id,
            body: RequestBody::FindNode {
                distances: vec![12],
            },
        });

        let encoded = request.clone().encode(&ticket_key);
        let decoded = Message::decode(&encoded, &ticket_key).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_nodes_response() {
        let ticket_key: [u8; 16] = rand::random();
        let key = enr::CombinedKey::generate_secp256k1();
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

        let encoded = request.clone().encode(&ticket_key);
        let decoded = Message::decode(&encoded, &ticket_key).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_talk_request() {
        let ticket_key: [u8; 16] = rand::random();
        let id = RequestId(vec![1]);
        let request = Message::Request(Request {
            id,
            body: RequestBody::Talk {
                protocol: vec![17u8; 32],
                request: vec![1, 2, 3],
            },
        });

        let encoded = request.clone().encode(&ticket_key);
        let decoded = Message::decode(&encoded, &ticket_key).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_register_topic_request_empty_ticket() {
        let ticket_key: [u8; 16] = rand::random();
        let port = 5000;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let key = enr::CombinedKey::generate_secp256k1();
        let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();

        let request = Message::Request(Request {
            id: RequestId(vec![1]),
            body: RequestBody::RegisterTopic {
                topic: "lighthouse".to_string(),
                enr,
                ticket: RequestTicket::Empty,
            },
        });

        let encoded = request.clone().encode(&ticket_key);
        let decoded = Message::decode(&encoded, &ticket_key).unwrap();

        assert_eq!(request, decoded);
    }

    #[test]
    fn encode_decode_ticket_transit() {
        let local_ticket_key: [u8; 16] = rand::random();
        let remote_ticket_key: [u8; 16] = rand::random();

        let port = 5000;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let key = enr::CombinedKey::generate_secp256k1();
        let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();

        let node_id = enr.node_id();
        let og_ticket = Ticket::new(
            node_id,
            ip,
            TopicHash::from_raw([1u8; 32]),
            Instant::now(),
            Duration::from_secs(11),
            //Duration::from_secs(25),
        );

        // The local node sends a ticket response
        let response = Message::Response(Response {
            id: RequestId(vec![1]),
            body: ResponseBody::Ticket {
                ticket: ResponseTicket::LocallyIssued(og_ticket.clone()),
                wait_time: 1u64,
                topic: "lighthouse".to_string(),
            },
        });

        let encoded_resp = response.encode(&local_ticket_key);

        // The response arrives at the remote peer
        let decoded_resp = Message::decode(&encoded_resp, &remote_ticket_key).unwrap();

        if let Message::Response(Response {
            id: _,
            body:
                ResponseBody::Ticket {
                    ticket: ResponseTicket::RemotelyIssued(ticket_bytes),
                    ..
                },
        }) = decoded_resp
        {
            // The remote peer returns the ticket to the issuer
            let request = Message::Request(Request {
                id: RequestId(vec![1]),
                body: RequestBody::RegisterTopic {
                    topic: "lighthouse".to_string(),
                    enr,
                    ticket: RequestTicket::RemotelyIssued(ticket_bytes),
                },
            });

            let encoded_req = request.encode(&remote_ticket_key);

            // The request arrives at the issuer who decodes it
            let decoded_req = Message::decode(&encoded_req, &local_ticket_key).unwrap();

            if let Message::Request(Request {
                id: _,
                body:
                    RequestBody::RegisterTopic {
                        topic: _,
                        enr: _,
                        ticket: RequestTicket::LocallyIssued(ticket),
                    },
            }) = decoded_req
            {
                assert_eq!(og_ticket, ticket);
            } else {
                panic!();
            }
        } else {
            panic!();
        }
    }

    #[test]
    fn encode_decode_request_ticket() {
        // Create the test values needed
        let port = 5000;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let key = enr::CombinedKey::generate_secp256k1();

        let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();
        let node_id = enr.node_id();
        let ticket = Ticket::new(
            node_id,
            ip,
            TopicHash::from_raw([1u8; 32]),
            Instant::now(),
            Duration::from_secs(11),
            //Duration::from_secs(25),
        );

        let encoded = RequestTicket::LocallyIssued(ticket.clone()).encode();

        let decoded = RequestTicket::decode(&encoded).unwrap();

        assert_eq!(RequestTicket::LocallyIssued(ticket), decoded);
    }

    #[test]
    fn encode_decode_request_ticket_with_encryption() {
        // Create the test values needed
        let port = 5000;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let key = enr::CombinedKey::generate_secp256k1();

        let enr = EnrBuilder::new("v4").ip(ip).udp4(port).build(&key).unwrap();
        let node_id = enr.node_id();
        let ticket = Ticket::new(
            node_id,
            ip,
            TopicHash::from_raw([1u8; 32]),
            Instant::now(),
            Duration::from_secs(11),
            //Duration::from_secs(25),
        );

        let ticket_key: [u8; 16] = rand::random();

        let encoded = RequestTicket::LocallyIssued(ticket.clone()).encode();

        let encrypted_ticket = {
            let aead = Aes128Gcm::new(GenericArray::from_slice(&ticket_key));
            let payload = Payload {
                msg: &encoded,
                aad: b"",
            };
            aead.encrypt(GenericArray::from_slice(&[1u8; 12]), payload)
                .unwrap()
        };

        let decrypted_ticket = {
            let aead = Aes128Gcm::new(GenericArray::from_slice(&ticket_key));
            let payload = Payload {
                msg: &encrypted_ticket,
                aad: b"",
            };
            aead.decrypt(GenericArray::from_slice(&[1u8; 12]), payload)
                .map_err(|e| error!("Failed to decode ticket in REGTOPIC query: {}", e))
        }
        .unwrap();

        let decoded = RequestTicket::decode(&decrypted_ticket).unwrap();

        assert_eq!(encoded, decrypted_ticket);
        assert_eq!(RequestTicket::LocallyIssued(ticket), decoded);
    }

    #[test]
    fn encode_decode_topic_query_request() {
        let ticket_key: [u8; 16] = rand::random();

        let request = Message::Request(Request {
            id: RequestId(vec![1]),
            body: RequestBody::TopicQuery {
                topic: TopicHash::from_raw([1u8; 32]),
            },
        });
        let encoded = request.clone().encode(&ticket_key);
        let decoded = Message::decode(&encoded, &ticket_key).unwrap();

        assert_eq!(request, decoded);
    }
}
