//! Session management for the Discv5 Discovery service.
//!
//! The [`Service`] is responsible for establishing and maintaining sessions with
//! connected/discovered nodes. Each node, identified by it's [`NodeId`] is associated with a
//! [`Session`]. This service drives the handshakes for establishing the sessions and associated
//! logic for sending/requesting initial connections/ENR's from unknown peers.
//!
//! The `Service` also manages the timeouts for each request and reports back RPC failures,
//! session timeouts and received messages. Messages are encrypted and decrypted using the
//! associated `Session` for each node.
//!
//! An ongoing connection is managed by [`Session`]. A node that provides and ENR with an
//! IP address/port that doesn't match the source, is considered untrusted. Once the IP is updated
//! to match the source, the `Session` is promoted to an established state. RPC requests are not sent
//! to untrusted Sessions, only responses.

use crate::config::Discv5Config;
use crate::error::Discv5Error;
use crate::packet::{AuthHeader, AuthTag, Magic, Nonce, Packet, Tag, TAG_LENGTH};
use crate::rpc::{Message, Request, RequestId, Response};
use crate::socket;
use crate::socket::Socket;
use crate::{Enr, Executor};
use enr::NodeId;
use futures::prelude::*;
use log::{debug, error, warn};
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::{collections::HashMap, default::Default, net::SocketAddr, time::Duration};
use tokio::sync::{mpsc, oneshot};

// mod tests;
mod crypto;
mod hashmap_delay;
mod session;

pub use crate::node_info::{NodeAddress, NodeContact};

use hashmap_delay::HashMapDelay;
pub use session::Session;

/// Events sent to the handler to be executed.
pub enum HandlerRequest {
    /// Sends a `Request` to a `NodeContact`. A `NodeContact` is an abstract type
    /// that allows for either an ENR to be sent or a `Raw` type which represents an `SocketAddr`,
    /// `PublicKey` and `NodeId`. This type can be created from MultiAddrs and MultiAddr strings
    /// for some keys.
    ///
    /// This permits us to send messages to nodes without knowing their ENR. In this case their ENR
    /// will be requested during the handshake.
    ///
    /// A Request is flagged and permits responses through the packet filter.
    ///
    /// Note: To update an ENR for an unknown node, we request a FINDNODE with distance 0 to the
    /// `NodeContact` we know of.
    Request(NodeContact, Request),

    /// Send a response to a received request to a particular node.
    ///
    /// The handler does not keep state of requests, so the application layer must send the
    /// response back to the `NodeAddress` from which the request was received.
    Response(NodeAddress, Response),

    /// A Random packet has been received and we have requested the application layer to inform
    /// us what the highest known ENR is for this node.
    /// The `WhoAreYouRef` is sent out in the `HandlerResponse::WhoAreYou` event and should
    /// be returned here to submit the application's response.
    WhoAreYou(WhoAreYouRef, Option<Enr>),
}

#[derive(Debug)]
/// The outputs provided by the `Handler`.
pub enum HandlerResponse {
    /// A session has been established with a node.
    ///
    /// A session is only considered established once we have received a signed ENR from the
    /// node and received messages from it's `SocketAddr` matching it's ENR fields.
    Established(Enr),

    /// A Request has been received.
    Request(NodeAddress, Request),

    /// A Response has been received.
    Response(Response),

    /// An unknown source has requested information from us. Return the reference with the known
    /// ENR of this node (if known). See the `HandlerRequest::WhoAreYou` variant.
    WhoAreYou(WhoAreYouRef),

    /// An RPC request failed.
    ///
    /// This returns the request ID and an error indicating why the request failed.
    RequestFailed(RequestId, RequestError),
}

pub enum RequestError {
    Timeout,
    InvalidEnr(String),
    EncryptionFailed(String),
}

/// A reference for the application layer to send back when the handler requests any known
/// ENR for the NodeContact.
pub struct WhoAreYouRef(pub NodeAddress, AuthTag);

pub struct Challenge {
    nonce: Nonce,
    remote_enr: Option<Enr>,
}

/// A smaller configuration set held by the Handler.
pub struct HandlerConfig {
    request_retries: u8,
    request_timeout: Duration,
}

impl<T: Executor> From<Discv5Config<T>> for HandlerConfig {
    fn from(config: Discv5Config<T>) -> Self {
        HandlerConfig {
            request_retries: config.request_retries,
            request_timeout: config.request_timeout,
        }
    }
}

#[derive(Debug)]
/// A request to a node that we are waiting for a response.
pub(crate) struct RequestCall {
    contact: NodeContact,
    /// The raw discv5 packet sent.
    packet: Packet,
    /// The unencrypted message. Required if need to re-encrypt and re-send.
    request: Request,
    /// Handshakes attempted.
    handshake_sent: bool,
    /// The number of times this request has been re-sent.
    retries: u8,
}

impl RequestCall {
    fn new(contact: NodeContact, packet: Packet, request: Request) -> Self {
        Request {
            contact,
            packet,
            request,
            handshakes: 0,
            retries: 1,
        }
    }

    fn id(&self) -> u64 {
        self.request.0
    }
}

pub struct Handler {
    /// Configuration for the discv5 service.
    config: HandlerConfig,
    /// The local ENR.
    enr: Arc<RwLock<Enr>>,
    /// The key to sign the ENR and set up encrypted communication with peers.
    key: enr::CombinedKey,
    /// Pending raw requests. A list of raw messages we are awaiting a response from the remote.
    /// These are indexed by SocketAddr as WHOAREYOU messages do not return a source node id to
    /// match against.
    active_requests: HashMapDelay<NodeAddress, RequestCall>,
    active_requests_auth: HashMap<AuthTag, NodeAddress>,
    /// Requests awaiting a handshake completion.
    pending_requests: HashMap<NodeAddress, Vec<Request>>,
    /// Currently in-progress handshakes with peers.
    active_challenges: LruCache<NodeAddress, Challenge>,
    /// Established sessions with peers.
    sessions: LruCache<NodeAddress, Session>,
    /// The channel that receives requests from the application layer.
    inbound_channel: mpsc::Receiver<HandlerRequest>,
    /// The channel to send responses to the application layer.
    outbound_channel: mpsc::Sender<HandlerResponse>,
    /// The discovery v5 UDP socket tasks.
    socket: Socket,
    /// Exit channel to shutdown the handler.
    exit: oneshot::Receiver<()>,
}

impl Handler {
    /// A new Session service which instantiates the UDP socket send/recv tasks.
    pub(crate) fn spawn<T: Executor>(
        enr: Arc<RwLock<Enr>>,
        key: enr::CombinedKey,
        listen_socket: SocketAddr,
        config: Discv5Config<T>,
    ) -> (
        oneshot::Sender<()>,
        mpsc::Sender<HandlerRequest>,
        mpsc::Receiver<HandlerResponse>,
    ) {
        let (exit_sender, exit) = oneshot::channel();
        // create the channels to send/receive messages from the application
        let (inbound_send, inbound_channel) = mpsc::channel(20);
        let (outbound_channel, outbound_recv) = mpsc::channel(20);

        // Creates a SocketConfig to pass to the underlying UDP socket tasks.

        // Generates the WHOAREYOU magic packet for the local node-id
        // Will be removed in update
        let magic = {
            let mut hasher = Sha256::new();
            hasher.input(enr.read().node_id().raw());
            hasher.input(b"WHOAREYOU");
            let mut magic: Magic = Default::default();
            magic.copy_from_slice(&hasher.result());
            magic
        };

        let socket_config = socket::SocketConfig {
            executor: config.executor,
            socket_addr: listen_socket,
            filter_config: config.filter_config,
            whoareyou_magic: magic,
        };

        let socket = socket::Socket::new(&socket_config);

        let handler = Handler {
            config: config.into(),
            enr,
            key,
            active_requests: HashMapDelay::new(config.request_timeout),
            pending_requests: HashMap::new(),
            sessions: LruCache::with_expiry_duration_and_capacity(
                config.session_timeout,
                config.session_cache_capacity,
            ),
            active_challenges: LruCache::with_expiry_duration(config.request_timeout * 2),
            inbound_channel,
            outbound_channel,
            socket,
            exit,
        };

        config.executor.spawn(async move {
            debug!("Handler Starting");
            handler.start().await;
        });

        (exit_sender, inbound_send, outbound_recv)
    }

    /// The main execution loop for the handler.
    async fn start(&mut self) {
        loop {
            tokio::select! {
                handler_request = self.inbound_channel => {
                    match handler_request {
                        HandlerRequest::Request(contact, request) => {
                           if let Err(request_error) =  self.send_request(contact, request).await {
                               // If the sending failed report to the application
                               self.outbound_channel.send(HandlerResponse::RequestFailed(request.id, request_error)).await;
                           }
                        }
                        HandlerRequest::Response(dst, response) => self.send_response(dst, response).await,
                        HandlerRequest::WhoAreYou(wru_ref, enr) => self.send_challenge(wru_ref, enr).await,
                    }
                }
                inbound_packet = self.socket.recv => {
                    self.process_inbound_packet(inbound_packet).await;
                }
                Some(Ok((node_address, pending_request))) = self.active_requests.next() => {
                    self.handle_request_timeout(node_address, pending_request).await;
                }
            }
        }
    }

    /// Processes an inbound decoded packet.
    async fn process_inbound_packet(&mut self, inbound_packet: socket::InboundPacket) {
        // TODO: Clean these up as NodeAddresses before handling with the new updates
        match inbound_packet.packet {
            Packet::WhoAreYou {
                auth_tag,
                id_nonce,
                enr_seq,
                ..
            } => {
                let _ = self
                    .handle_challenge(inbound_packet.src, auth_tag, id_nonce, enr_seq)
                    .await;
            }
            Packet::AuthMessage {
                tag,
                auth_header,
                message,
            } => {
                let _ = self
                    .handle_auth_message(inbound_packet.src, tag, auth_header, &message)
                    .await;
            }
            Packet::Message {
                tag,
                auth_tag,
                message,
            } => {
                let src_id = self.src_id(&tag);
                let node_address = NodeAddress {
                    node_id: src_id,
                    socket_addr: inbound_packet.src,
                };
                let _ = self
                    .handle_message(node_address, auth_tag, &message, tag)
                    .await;
            }
            Packet::RandomPacket { .. } => {} // this will not be decoded.
        }
    }

    async fn fail_session(&mut self, node_address: &NodeAddress) {
        self.sessions.remove(&node_address);
        for request in self
            .pending_requests
            .remove(&node_address)
            .unwrap_or_else(|| Vec::new())
        {
            self.outbound_channel
                .send(HandlerResponse::RequestFailed(
                    request.id,
                    RequestError::Timeout,
                ))
                .await;
        }
    }

    /// A request has timed out.
    async fn handle_request_timeout(
        &mut self,
        node_address: NodeAddress,
        request_call: RequestCall,
    ) {
        if request_call.retries >= self.config.request_retries {
            // The Request has expired, remove the session.
            let auth_tag = request_call
                .packet
                .auth_tag()
                .expect("No challenge packets here");
            // Remove from the auth_tag mapping also.
            self.active_requests_auth.remove(auth_tag);
            self.fail_session(&node_address);
        } else {
            // increment the request retry count and restart the timeout
            debug!(
                "Resending message: {} to {}",
                request_call.request, node_address
            );
            self.send(
                node_address.socket_addr.clone(),
                request_call.packet.clone(),
            );
            request_call.retries += 1;
            self.active_requests.insert(node_address, request_call);
        }
    }

    /// Sends a `Request` to a node.
    async fn send_request(
        &mut self,
        contact: NodeContact,
        request: Request,
    ) -> Result<(), RequestError> {
        let node_address = contact
            .node_address()
            .map_err(|e| RequestError::InvalidEnr(e.into()))?;

        // If there is already an active request for this node, add to pending requests
        if self.active_requests.get(&node_address).is_some() {
            debug!(
                "Session is being established, request queued for node: {}",
                node_address
            );
            self.pending_requests
                .entry(node_address)
                .or_insert_with(|| Vec::new())
                .push(request);
            return Ok(());
        }

        let packet = {
            if let Some(session) = self.sessions.get(&node_address) {
                // Encrypt the message and send
                session
                    .encrypt_message(self.tag(&node_address.node_id), &request.encode())
                    .map_err(|e| RequestError::EncryptionFailed(format!("{:?}", e)))?
            } else {
                // No session exists, start a new handshake
                debug!(
                    "Starting session. Sending random packet to: {}",
                    node_address
                );
                Packet::random(self.tag(&node_address.node_id))
            }
        };

        let call = RequestCall::new(contact, packet.clone(), request);
        let auth_tag = call.packet.auth_tag().expect("No challenges here").clone();
        self.active_requests_auth
            .insert(auth_tag, node_address.clone());
        self.active_requests.insert(node_address, call);
        self.send(node_address.socket_addr.clone(), packet).await;
        Ok(())
    }

    /// Sends an RPC Response.
    async fn send_response(&mut self, node_address: NodeAddress, response: Response) {
        // Check for an established session
        if let Some(session) = self.sessions.get(&node_address) {
            // Encrypt the message and send
            let packet = match session
                .encrypt_message(self.tag(&node_address.node_id), &response.encode())
            {
                Ok(packet) => packet,
                Err(e) => {
                    warn!("Could not encrypt response: {:?}", e);
                    return;
                }
            };
            self.send(node_address.socket_addr, packet).await;
        } else {
            // Either the session is being established or has expired. We simply drop the
            // response in this case.
            warn!(
                "Session is not established. Dropping response {} for node: {}",
                response, node_address.node_id
            );
        }
    }

    /// This is called in response to a `HandlerResponse::WhoAreYou` event. The applications finds the
    /// highest known ENR for a node then we respond to the node with a WHOAREYOU packet.
    async fn send_challenge(&mut self, wru_ref: WhoAreYouRef, mut remote_enr: Option<Enr>) {
        let node_address = wru_ref.0;
        let auth_tag = wru_ref.1;

        if self.active_challenges.get(&node_address).is_some() {
            warn!("WHOAREYOU already sent. Node: {}", wru_ref.0.node_id);
            return;
        }

        // Ignore this request if the session is already established
        if self.sessions.get(&node_address).is_some() {
            debug!(
                "Session already established. WHOAREYOU not sent to {}",
                wru_ref.0
            );
            return;
        }

        // It could be the case we have sent an ENR with an active request, however we consider
        // these independent as this is in response to an unknown packet. If the ENR it not in our
        // table (remote_enr is None) then we re-request the ENR to keep the session up to date.

        // send the challenge
        let enr_seq = remote_enr.map(|enr| enr.seq()).unwrap_or_else(|| 0);
        let (packet, nonce) = Packet::whoareyou(node_address.node_id, enr_seq, auth_tag);
        self.active_challenges
            .insert(node_address, Challenge { nonce, remote_enr });
        self.send(node_address.socket_addr, packet).await;
    }

    /// Calculates the src `NodeId` given a tag.
    fn src_id(&self, tag: &Tag) -> NodeId {
        let hash = Sha256::digest(&self.enr.node_id().raw());
        let mut src_id: [u8; 32] = Default::default();
        for i in 0..32 {
            src_id[i] = hash[i] ^ tag[i];
        }
        NodeId::new(&src_id)
    }

    /// Calculates the tag given a `NodeId`.
    fn tag(&self, dst_id: &NodeId) -> Tag {
        let hash = Sha256::digest(&dst_id.raw());
        let mut tag: Tag = Default::default();
        for i in 0..TAG_LENGTH {
            tag[i] = hash[i] ^ self.enr.node_id().raw()[i];
        }
        tag
    }

    /* Packet Handling */

    // TODO: Pending requests can be stored via node id in the future.
    /// Handles a WHOAREYOU packet that was received from the network.
    async fn handle_challenge(
        &mut self,
        src: SocketAddr,
        token: AuthTag,
        id_nonce: Nonce,
        enr_seq: u64,
    ) {
        // It must come from a source that we have an outgoing message to and match an
        // authentication tag
        let request_call = {
            match self.active_requests_auth.remove(&token) {
                None => {
                    debug!("Received a WHOAREYOU packet that references an unknown or expired request. source: {:?}, auth_tag: {}", src, hex::encode(token));
                    return;
                }
                Some(address) => {
                    if address.socket_addr != src {
                        warn!("Invalid source responding to message. Dropping. Source: {:?}, expected: {}", src, address.socket_addr);
                        self.active_requests_auth.insert(token, address);
                        return;
                    } else {
                        self.active_requests
                            .remove(&address)
                            .expect("Active requests maps should be in sync")
                    }
                }
            }
        };

        debug!("Received a WHOAREYOU packet. Source: {}", src);

        let seen_node_address = NodeAddress {
            socket_addr: src,
            node_id: request_call.contact.node_id(),
        };
        let node_address = request_call
            .contact
            .node_address()
            .expect("Request call's are sanitized. Must have valid ENR");

        if request_call.handshake_sent {
            warn!(
                "Auth response already sent. Dropping session. Node: {}",
                node_address.node_id
            );
            self.fail_session(&node_address);
            return;
        }

        // Encrypt the message with an auth header and respond
        //
        // First if a new version of our ENR is requested, obtain it for the header
        let updated_enr = if enr_seq < self.enr.read().seq() {
            Some(self.enr.read().clone())
        } else {
            None
        };

        let src_id = request_call.contact.node_id();
        let tag = self.tag(&src_id);

        // Generate a new session and authentication packet
        // TODO: Remove tags in the update
        let (auth_packet, session) = match Session::encrypt_with_header(
            tag,
            request_call.contact,
            &self.key,
            updated_enr,
            &self.enr.read().node_id(),
            &id_nonce,
            &request_call.request,
        ) {
            Ok(v) => v,
            Err(e) => {
                error!("Could not generate a session. Error: {:?}", e);
                self.fail_session(&node_address);
                return;
            }
        };

        // New session has been established
        debug!(
            "Sending Authentication response to node: {}",
            request_call.contact.node_id()
        );
        request_call.packet = auth_packet;
        request_call.handshake_sent = true;
        // re_insert the request_call
        self.active_requests.insert(request_call.contact.node);
        self.send(node_address.socket_addr, auth_packet).await;
    }

    /// Handle a message that contains an authentication header.
    async fn handle_auth_message(
        &mut self,
        src: SocketAddr,
        tag: Tag,
        auth_header: AuthHeader,
        message: &[u8],
    ) -> Result<(), ()> {
        // Needs to match an outgoing challenge packet (so we have the required nonce to be signed). If it doesn't we drop the packet.
        // This will lead to future outgoing challenges if they proceed to send further encrypted
        // packets.
        let src_id = self.src_id(&tag);
        debug!("Received an Authentication header message from: {}", src_id);

        let node_address = NodeAddress {
            socket_addr: src,
            node_id: src_id,
        };

        if let Some(challenge) = self.challenges.remove(&node_address) {
            match Session::establish_from_header(
                &self.key,
                &self.enr.read().node_id(),
                &src_id,
                challenge,
                &auth_header,
            ) {
                Ok(session) => {
                    self.new_session(node_address, session);
                    self.handle_message(node_address, message);
                }
                Err(e) => {
                    warn!(
                        "Invalid Authentication header. Dropping session. Error: {:?}",
                        e
                    );
                    self.sessions.remove(&src_id);
                    return Err(());
                }
            }
        } else {
            warn!(
                "Received an authenticated header without a matching WHOAREYOU request. {}",
                node_address
            );
            return;
        }
    }

    fn new_session(&mut self, node_address: NodeAddress, session: Session) {
        if let Some(current_session) = self.sessions.get_mut(node_address) {
            current_session.update(session);
        } else {
            self.session.insert(node_address, session);
        }
    }

    /// Handle a standard message that does not contain an authentication header.
    async fn handle_message(
        &mut self,
        node_address: NodeAddress,
        auth_tag: AuthTag,
        message: &[u8],
        tag: Tag,
    ) {
        // check if we have an available session
        if let Some(session) = self.sessions.get_mut(&node_address) {
            // drop the packet and blacklist the peer if the node_address doesn't match the
            // Session's ENR
            // TODO: blacklist
            if let Some(enr) = session.enr {
                if let Some(socket_addr) = enr.socket_addr() {
                    if socket_addr != node_address.socket_addr {
                        warn!(
                            "Peer's ENR SocketAddr doesn't match observed. ENR: {:?}, Observed {}",
                            socket_addr, node_address
                        );
                        self.sessions.remove(node_address);
                        self.fail_requests(node_address);
                        return;
                    }
                }
            }

            // attempt to decrypt and process the message.
            let message = match session.decrypt_message(auth_tag, message, &tag) {
                Ok(m) => match Message::decode(m) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to decode message. Error: {:?}", e);
                        return;
                    }
                },
                Err(_) => {
                    // We have a session, but the message could not be decrypted. It is likely the node
                    // sending this message has dropped their session. In this case, this message is a
                    // Random packet and we should reply with a WHOAREYOU.
                    // This means we need to drop the current session and re-establish.
                    debug!("Message from node: {} is not encrypted with known session keys. Requesting a WHOAREYOU packet", node_address);
                    self.sessions.remove(&node_address);
                    // spawn a WHOAREYOU event to check for highest known ENR
                    let whoareyou_ref = WhoAreYouRef {
                        node_address,
                        auth_tag,
                    };
                    self.outbound_channel
                        .send(HandlerResponse::WhoAreYou(whoareyou_ref))
                        .await;
                    return Ok(());
                }
            };

            // Remove any associated request from pending_request
            match message {
                Message::Request(request) => {
                    // report the request to the application
                    self.outbound_channel
                        .send(HandlerResponse::Request(request))
                        .await;
                }
                Message::Response(response) => {
                    if self
                        .active_requests
                        .remove(&node_address, |req| req.id() == Some(message.id))
                        .is_some()
                    {
                        // report the response
                        self.outbound_channel
                            .send(HandlerResponse::Response(response))
                            .await;
                        self.send_next_request(node_address);
                    } else {
                        debug!("Late response from node: {}", node_address);
                    }
                }
            }

            if !session.trusted {
                if let Some(enr) = session.enr {
                    if let Some(socket_addr) = enr.socket_addr() {
                        if socket_addr == node_address.socket_addr {
                            debug!("Session established. Node {}", node_address);
                            session.trusted = true;
                            self.outbound_channel
                                .send(HandlerResponse::Established(enr))
                                .await;
                        }
                    }
                }
            }
        } else {
            // no session exists
            debug!("Received a message without a session. {}", node_address);
            debug!("Requesting a WHOAREYOU packet to be sent.");
            // spawn a WHOAREYOU event to check for highest known ENR
            let whoareyou_ref = WhoAreYouRef {
                node_address,
                auth_tag,
            };
            self.outbound_channel
                .send(HandlerResponse::WhoAreYou(whoareyou_ref))
                .await;
        }
    }

    /// Sends a packet to the send handler to be encoded and sent.
    async fn send(&mut self, dst: SocketAddr, packet: Packet) {
        let outbound_packet = socket::OutboundPacket { dst, packet };
        self.socket.send.send(outbound_packet).await;
    }
}
