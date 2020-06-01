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


use super::transport::Transport;
use crate::config::Discv5Config;
use crate::error::Discv5Error;
use crate::packet::{AuthHeader, AuthTag, Magic, Nonce, Packet, Tag, TAG_LENGTH};
use crate::rpc::ProtocolMessage;
use crate::session::Session;
use crate::Enr;
use enr::{EnrError, NodeId};
use futures::prelude::*;
use log::{debug, error, trace, warn};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    default::Default,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

mod tests;
mod timed_requests;
mod timed_sessions;

use timed_requests::TimedRequests;
use timed_sessions::TimedSessions;


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
    WhoAreYou(WhoAreYouRef, Option<Enr>)
}

#[derive(Debug)]
/// The outputs provided by the `Handler`.
pub(crate) enum HandlerResponse {
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

/// A reference for the application layer to send back when the handler requests any known
/// ENR for the NodeContact.
pub struct WhoAreYouRef(pub NodeAddress, AuthTag);

/// A smaller configuration set held by the Handler.
struct HandlerConfig {
    request_retries: usize,
    request_timeout: Duration,
}

impl From<Discv5Config> for HandlerConfig {
    fn from(config: Discv5Config) -> Self {
        request_retreis = config.request_retries,
        request_timeout = config.request_timeout,
    }
}

#[derive(Debug)]
/// A request to a node that we are waiting for a response.
pub(crate) struct PendingRequest {
    /// The raw discv5 packet sent.
    packet: Packet,

    /// The unencrypted message. Required if need to re-encrypt and re-send.
    request: Option<Request>,

    /// The number of times this request has been re-sent.
    retries: u8,
}

impl PendingRequest {
    fn new(packet: Packet, message: Option<Request>) -> Self {
        Request {
            packet,
            message,
            retries: 1,
        }
    }

    fn id(&self) -> Option<u64> {
        self.request.as_ref().map(|m| m.0)
    }
}

pub(crate) struct Handler<T: Executor> {
    /// Configuration for the discv5 service.
    config: HandlerConfig,
    /// The local ENR.
    enr: Arc<RwLock<Enr>>,
    /// The key to sign the ENR and set up encrypted communication with peers.
    key: enr::CombinedKey,
    /// Pending raw requests. A list of raw messages we are awaiting a response from the remote.
    /// These are indexed by SocketAddr as WHOAREYOU messages do not return a source node id to
    /// match against.
    pending_requests: TimedRequests,
    /// Sessions that have been created for each node id. These can be established or
    /// awaiting response from remote nodes.
    sessions: Sessions,
    /// The channel that receives requests from the application layer.
    inbound_channel: tokio::mpsc::Receiver<HandlerRequest>,
    /// The channel to send responses to the application layer.
    outbound_channel: tokio::mpsc::Sender<HandlerResponse>,
    /// The discovery v5 UDP socket tasks.
    socket: Socket<T>,
    /// Exit channel to shutdown the handler.
    exit: tokio::oneshot::Receiver,
}

impl Service {

    /// A new Session service which instantiates the UDP socket send/recv tasks.
    pub(crate) fn spawn(
        enr: Enr<CombinedKey>,
        key: enr::CombinedKey,
        listen_socket: SocketAddr,
        outbound_channel: tokio::mpsc::Sender<HandlerResponse>,
        config: Discv5Config,
    ) -> tokio::oneshot::Sender, tokio::mpsc::Sender<HandlerRequest> {

        let (exit_sender, exit) = tokio::oneshot::channel();
        // create the channel to receive messages from the application
        let (handler_inbound_sender, inbound_channel) = tokio::mpsc::channel(10);

        // Creates a SocketConfig to pass to the underlying UDP socket tasks.

        // generates the WHOAREYOU magic packet for the local node-id
        // Will be removed in update
        let magic = {
            let mut hasher = Sha256::new();
            hasher.input(enr.node_id().raw());
            hasher.input(b"WHOAREYOU");
            let mut magic: Magic = Default::default();
            magic.copy_from_slice(&hasher.result());
            magic
        };

        let socket_config = socket::SocketConfig {
            executor: executor
            socket_addr: listen_socket,
            filter_config: config.filter_config,
            whoareyou_magic: magic
        };

        let socket = socket::Socket::new(&socket_config);

        let service = Service {
            events: VecDeque::new(),
            config,
            enr,
            key,
            pending_requests: TimedRequests::new(config.request_timeout),
            sessions: Sessions::new(config.session_timeout, config.session_capacity),
            inbound_channel,
            outbound_channel,
            socket,
            exit,
        };

        config.executor.spawn(async move {
            debug!("Handler Starting")
            service.start().await;
        });

        exit_sender
    }


    /// The main execution loop for the handler.
    async fn run(&mut self) {
        loop {
            tokio::select! {
                handler_request = self.inbound_channel => {
                    match handler_request {
                        HandlerRequest::Request(contact, request) => {
                           if let Err(request_error) =  self.send_request(contact, request).await {
                               // If the sending failed report to the application
                               self.outbound_channel.send(HandlerResponse::RequestFailed(request.0), request_error).await;
                           }
                        }
                        HandlerRequest::Response(dst, response) => self.send_response(dst, response).await
                        HandlerRequest::WhoAreYou(wru_ref, enr) => self.send_whoareyou(wru_ref, enr).await
                    }
                }
                socket_packet = self.socket.recv => {
                    self.process_inbound_packet().await;
                }
                (node_address, pending_request) = self.pending_requests.next() => {
                    self.handle_request_timeout(node_address, pending_request).await;
                }
            }
        }
    }


    /// Processes an inbound decoded packet.
    async fn process_inbound_packet(&mut self, inbound_packet: InboundPacket) {
        // TODO: Clean these up as NodeAddresses before handling with the new updates
                    match inbound_packet.1 {
                        Packet::WhoAreYou {
                            token,
                            id_nonce,
                            enr_seq,
                            ..
                        } => {
                            let _ = self.handle_whoareyou(inbound_packet.0, token, id_nonce, enr_seq).await;
                        }
                        Packet::AuthMessage {
                            tag,
                            auth_header,
                            message,
                        } => {
                            let _ = self.handle_auth_message(inbound_packet.0, tag, auth_header, &message).await;
                        }
                        Packet::Message {
                            tag,
                            auth_tag,
                            message,
                        } => {
                            let src_id = self.src_id(&tag);
                            let _ = self.handle_message(src, src_id, auth_tag, &message, tag).await;
                        }
                        Packet::RandomPacket { .. } => {} // this will not be decoded.
                    }
            }


    /// A request has timed out.
    async fn handle_request_timeout(&mut self, node_address: NodeAdress, pending_request: PendingRequest) {
            if pending_request.retries >= self.config.request_retries {
                // The Request has expired, remove the session.
                match self.session.remove_session(&node_address, &pending_request) {
                    SessionRemoved::Establishing(failed_requests) => {
                            debug!("Session couldn't be established with Node: {}", node_address.node_id);
                            for request in failed_requests {
                                self.outbound_channel.send(HandlerResponse::RequestFailed(req.0, RequestError::Timeout)).await;
                            }
                    }
                    SessionRemoved::Established => {
                        // An established session has been removed due to a non-response from a
                        // node.
                        debug!("Message timed out with node: {}", node_id);
                        self.outbound_channel.send(HandlerResponse::RequestFailed(pending_request.id(), RequestError::Timeout)).await;
                    }
                    SessionRemoved::NotFound => {
                        error!("There was no session associated with an expired request to node: {}", node_address.node_id);
                        self.outbound_channel.send(HandlerResponse::RequestFailed(pending_request.id(), RequestError::Timeout)).await;
                    }
                }
            } else {
                // increment the request retry count and restart the timeout
                debug!(
                    "Resending message: {} to node: {}",
                    request.packet, node_id
                );
                self.send(dst.clone(), pending_request.packet.clone());
                pending_request.retries += 1;
                self.pending_requests.insert(dst, pending_request);
            }
    }

    /* Handler request message handling */
    /*
    /// Updates the local ENR `SocketAddr` for either the TCP or UDP port.
    pub(crate) fn update_local_enr_socket(
        &mut self,
        socket: SocketAddr,
        is_tcp: bool,
    ) -> Result<(), EnrError> {
        // determine whether to update the TCP or UDP port
        if is_tcp {
            self.enr.set_tcp_socket(socket, &self.key).map_err(|e| {
                warn!("Could not update the ENR IP address. Error: {:?}", e);
                e
            })
        } else {
            // Update the UDP socket
            self.enr.set_udp_socket(socket, &self.key).map_err(|e| {
                warn!("Could not update the ENR IP address. Error: {:?}", e);
                e
            })
        }
    }


    /// Updates a session if a new ENR or an updated ENR is discovered.
    pub(crate) fn update_enr(&mut self, enr: Enr<CombinedKey>) {
        if let Some(session) = self.sessions.get_mut(&enr.node_id()) {
            // if an ENR is updated to an address that was not the last seen address of the
            // session, we demote the session to untrusted.
            if session.update_enr(enr.clone()) {
                // A session have been promoted to established. Noftify the protocol
                self.events.push_back(ServiceEvent::Established(enr));
            }
        }
    }
    */

    /// Sends a `Request` to a node.
    ///
    async fn send_request(
        &mut self,
        contact: NodeContact,
        request: Request,
    ) -> Result<(), RequestError> {

        let node_id = contact.node_id;
        let socket_addr = contact.udp_socket().map_err(|e| RequestError::InvalidEnr(e))?;
        let node_address = NodeAddress { socket_addr, node_id };

        // Check for an established session
        // This removes expired sessions if no pending request exists
        match self.sessions.notify_get_mut(&node_id, &self.pending_requests) {
            Session::Random(session) | Session::WhoAreYou(session) => {
                // We are currently establishing a connection,
                // Add this message to the establishing sessions queue.

                session.pending_requests.push(request);
                debug!("Session is being established, request queued for node: {}", node_id);
            }
            Session::NotFound => {
                debug!("Starting session. Sending random packet to: {}", dst_id);

                // create a new establishing session
                self.sessions.new_random(contact, request);
                // send a random packet
                self.process_request(node_address, Packet::random(self.tag(&dst_id), None).await;
            }
            Session::Established(session) | Session::Untrusted(session) => {
                    // A session is already established
                    // Encrypt the message and send
                    let packet = session.encrypt_message(self.tag(&dst_id), request.encode())
                        .map_err(|e| RequestError::EncryptionFailed(e))?;

                    self.process_request(node_address, packet, Some(message)).await;
            }
        }
        Ok(())
    }

    /// Sends an RPC Response.
    async fn send_response(
        &mut self,
        node_address: NodeAddress,
        response: Response
    ) -> Result<(), Discv5Error> {

        // Check for an established session
        // This removes expired sessions if no pending request exists
        match self.sessions.notify_get_mut(&node_address.node_id, &self.pending_requests) {
            Session::Random(_) | Session::WhoAreYou(_) |  Session::NotFound => {
                // Either the session is being established or has expired. We simply drop the
                // response in this case.
                warn!("Session is not established. Dropping response {} for node: {}", node_address.node_id);
            }
            Session::Established(session) | Session::Untrusted(session) => {
                    // A session is already established
                    // Encrypt the message and send
                    let packet = session.encrypt_message(self.tag(&dst_id), request.encode())
                        .map_err(|e| RequestError::EncryptionFailed(e))?;
                    self.send(node_address.socket_addr, packet).await;
            }
        }
        Ok(())
    }

    /// This is called in response to a `HandlerResponse::WhoAreYou` event. The applications finds the
    /// highest known ENR for a node then we respond to the node with a WHOAREYOU packet.
    async fn send_whoareyou(
        &mut self,
        wru_ref: WhoAreYouRef
        mut remote_enr: Option<Enr<CombinedKey>>,
    ) {
        let node_address = wru_ref.0;
        let auth_tag = wru.1;

        // If a WHOAREYOU is already sent or a session is already established, ignore this request.
        // However if a random packet was sent with a known ENR and this request has no known
        // ENR. Use the ENR of the previously established Session.
        match self.sessions.notify_get_mut(&node_address.node_id, &self.pending_requests) {
            Session::Random(random_session) => {
                        // Upgrades the session to a WHOAREYOU session
                        random_session.whoareyou_sent();
                        // WHOAREYOU packet to send
                        let packet = Packet::whoareyou(node_address.node_id, enr_seq, auth_tag);
                        self.process_request(node_address, packet, None).await;
                    },
            Session::WhoAreYou(_) => {
                        warn!("WHOAREYOU already sent. Node: {}", wru_ref.0.node_id);
                        return;
            }
            Session::Established(_) | Session::Untrusted(_) => {
                        debug!("Session already established. WHOAREYOU not sent to node: {}", wru_ref.0.node_id);
                        return;
            }
            Session::NotFound =>  {
                // Creates a new session in the WHOAREYOU Sent state.
                let enr_seq = self.local_enr.read().seq;
                let packet = Packet::whoareyou(node_address.node_id, enr_seq, auth_tag);
                let contact = remote_enr.map(|enr| enr.into());
                self.sessions.new_whoareyou(contact);
                self.process_request(node_address, whoareyou, None).await;
            }
        }
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
    async fn handle_whoareyou(
        &mut self,
        src: SocketAddr,
        token: AuthTag,
        id_nonce: Nonce,
        enr_seq: u64,
    ) -> Result<(),()> {
        // It must come from a source that we have an outgoing message to and match an
        // authentication tag
        let req = self.pending_requests.remove(&src, |req| req.packet.auth_tag() == Some(&token)).ok_or_else(|| {
            debug!("Received a WHOAREYOU packet that references an unknown or expired request. source: {:?}, auth_tag: {}", src, hex::encode(token));
        })?;

        debug!("Received a WHOAREYOU packet. Source: {}", src);

        // This is an assumed NodeId. We sent the packet to this NodeId and can only verify it against the
        // originating IP address. We assume it comes from this NodeId.
        let src_id = req.dst_id;
        let tag = self.tag(&src_id);

        // Update the ENR record if necessary
        let updated_enr = if enr_seq < self.enr.read().seq() {
            Some(self.enr.read().clone())
        } else {
            None
        };

        let node_address = NodeAddress { socket_addr: src, node_id: src_id };

        // Find the session associated with this and send the authentication response
        // either dropping the session or upgrading it to an AwaitingSession.
        match self.sessions.notify_remove(&node_address.node_id, &self.pending_requests) {
            Session::NotFound => {
                warn!("Received a WHOAREYOU packet without having an established session.");
                return;
            }
            Session::WhoAreYou(_) => {
                // We shouldn't receive a WHOAREYOU request that matches an outgoing request AND have a
                // session that is in a WHOAREYOU_SENT state. If this is the case, drop the packet.
                warn!("Received a WHOAREYOU packet whilst in a WHOAREYOU session state. Source: {}, node: {}", src, src_id);
                return;
            }
            Session::Random(random_session) => {
                // Generate an AuthResponse with the first pending message.

                // update the last seen socket
                random_session.set_last_seen_socket(src);

                // double check that the referenced request was a random packet
                if !req.packet.is_random() {
                    warn!("Received a WhoAreYou packet to a Random Session that references a non-random packet: {} Node: {}", req.packet, src_id);
                    return;
                }

        // Generate session keys and encrypt the earliest packet with the authentication header
        // An establishing session may have extra pending messages. We send these also, now that a
        // tentative session has been established.
        let (auth_packet, request, awaiting_session) = match random_session.encrypt_with_header(
            tag,
            &self.key,
            updated_enr,
            &self.enr.node_id(),
            &id_nonce,
        ) {
            Ok(p) => p,
            Err(e) => {
                error!("Could not generate a session. Error: {:?}", e);
                return;
            }
        };

        // Send the authentication response
        debug!("Sending Authentication response to node: {}", node_address.node_id);
        self.process_request(node_address.clone(), auth_packet, Some(request)).await;

        // Process any further pending requests
        for (packet, request) in awaiting_session.drain_pending_requests() {
            debug!("Sending {} to node: {}", request,node_address.node_id);
            self.process_request(node_address.clone(), packet, Some(request)).await;
        }
        }
        Session::Untrusted(session) | Session::Established(session) => {
            // Generate an auth response with the packet we previously sent
            // update the last seen socket
            session.set_last_seen_socket(src);
        // Generate session keys and encrypt the earliest packet with the authentication header
        let packet = match session.encrypt_with_header(
            tag,
            &self.key,
            updated_enr,
            &self.enr.node_id(),
            &id_nonce,
            req.packet
        ) {
            Ok(p) => p,
            Err(e) => {
                error!("Could not generate a session. Error: {:?}", e);
                return;
            }
        };

        // Send the authentication response
        debug!("Sending Authentication response to node: {}", node_address.node_id);
        self.process_request(node_address.clone(), auth_packet, Some(message)).await;
        }
        }
    }

    /// Handle a message that contains an authentication header.
    async fn handle_auth_message(
        &mut self,
        src: SocketAddr,
        tag: Tag,
        auth_header: AuthHeader,
        message: &[u8],
    ) -> Result<(), ()> {

        // Needs to match an outgoing WHOAREYOU packet (so we have the required nonce to be signed). If it doesn't we drop the packet. This will
        // lead to future outgoing WHOAREYOU packets if they proceed to send further encrypted
        // packets.
        let src_id = self.src_id(&tag);
        debug!("Received an Authentication header message from: {}", src_id);

        // This can promote the session to an established session. Keep track here if we do.
        let mut session_promoted = false;

        // Find the session associated with this and send the authentication response
        match self.sessions.notify_get_mut(&node_address.node_id, &self.pending_requests) {
            Session::NotFound | Session::Random(_) | Session::Untrusted(_) | Session::Established(_) => {
                warn!("Received an authenticated header without a known WHOAREYOU session. Dropping. Node: {} ", src_id);
                return Err(());
            }
            Session::WhoAreYou(establishing_session) => {

            // find the id_nonce from the whoareyou request
            let id_nonce = self
                .pending_requests
                .remove(&src, |req| {
                    req.packet.is_whoareyou() && req.dst_id == src_id
                })
                .map(|req| {
                    // get the nonce from the whoareyou
                    if let Packet::WhoAreYou { id_nonce, .. } = req.packet {
                        id_nonce }
                    else {
                        unreachable!("Coding error if there is not a WHOAREYOU packet in this request"),
                    }
                })
                .ok_or_else(|| {
                    warn!("Received an authenticated header without a matching WHOAREYOU request");
                })?;

            // update the sessions last seen socket
            session.set_last_seen_socket(src);

        // establish the session
        match establishing_session.establish_from_header(
            &self.key,
            &self.enr.node_id(),
            &src_id,
            id_nonce,
            &auth_header,
        ) {
            Ok(enr) => {
                // update whether the session was promoted
                session_promoted = promoted;
                // Notify the application that we have an established session
                trace!("Session established with node: {}", src_id);
                self.outbound_channel.send(HandlerResponse::Established(
                    establishing_session
                        .remote_enr()
                        .clone()
                        .expect("ENR exists when session is established"),
                ).await;

                // drain any pending requests for this session.
                for (packet, request) in establishing_session.drain_pending_requests() {
                    debug!("Sending {} to node: {}", request,node_address.node_id);
                    self.process_request(node_address.clone(), packet, Some(request)).await;
                }
            }
            Err(e) => {
                warn!("Invalid Authentication header. Dropping session. Error: {:?}", e);
                self.sessions.remove(&src_id);
                return Err(());
            }
        }
        // Session has been promoted to established. Update it to the established cache.
        // This updates the session from an `EstablishingSession` to a `Session` and moves it in
        // the underlying LruCache.
        self.sessions.update_established(&src_id);

        // decrypt the message
        // continue on error
        let _ = self.handle_message(src, src_id.clone(), auth_header.auth_tag, message, tag);

        Ok(())
    }

    /// Handle a standard message that does not contain an authentication header.
    fn handle_message(
        &mut self,
        src: SocketAddr,
        src_id: NodeId,
        auth_tag: AuthTag,
        message: &[u8],
        tag: Tag,
    ) -> Result<(), ()> {
        // check if we have an available session
        let events_ref = &mut self.events;
        let session = self.sessions.get_mut(&src_id).ok_or_else(|| {
            // no session exists
            debug!(
                "Received a message without a session. From: {:?}, node: {}",
                src, src_id
            );
            debug!("Requesting a WHOAREYOU packet to be sent.");
            // spawn a WHOAREYOU event to check for highest known ENR
            let event = ServiceEvent::WhoAreYouRequest {
                src,
                src_id,
                auth_tag,
            };
            events_ref.push_back(event);
        })?;

        // If the session has not been established, we cannot decrypt the message. For now we
        // proceed with trying to generate a handshake and drop the current received message.

        // There are two pre-established session states. RandomPacket set, or a WhoAreYou packet
        // sent.
        if session.is_random_sent() {
            // We have sent a RandomPacket and are expecting a WhoAreYou in response but received a
            // regular message. This can happen if a session has locally dropped. Instead of
            // waiting for the WhoAreYou response, we drop the current pending RandomPacket request
            // and upgrade the session to a WhoAreYou session.
            debug!("Old message received for non-established session. Upgrading to WhoAreYou. Source: {}, node: {}", src, src_id);
            if self
                .pending_requests
                .remove(&src, |req| req.packet.is_random())
                .is_none()
            {
                warn!(
                    "No random packet pending for a random session. Source: {}, node: {}",
                    src, src_id
                );
            }
            let event = ServiceEvent::WhoAreYouRequest {
                src,
                src_id,
                auth_tag,
            };
            self.events.push_back(event);
            return Ok(());
        }
        // return if we are awaiting a WhoAreYou packet
        else if session.is_whoareyou_sent() {
            debug!("Waiting for a session to be generated.");
            // potentially store and decrypt once we receive the packet.
            // drop it for now.
            return Ok(());
        }

        // we could be in the AwaitingResponse state. If so, this message could establish a new
        // session with a node. We keep track to see if the decryption updates the session. If so,
        // we notify the user and flush all cached messages.
        let session_was_awaiting = session.is_awaiting_response();

        // attempt to decrypt and process the message.
        let message = match session.decrypt_message(auth_tag, message, &tag) {
            Ok(m) => ProtocolMessage::decode(m)
                .map_err(|e| warn!("Failed to decode message. Error: {:?}", e))?,
            Err(_) => {
                // We have a session, but the message could not be decrypted. It is likely the node
                // sending this message has dropped their session. In this case, this message is a
                // Random packet and we should reply with a WHOAREYOU.
                // This means we need to drop the current session and re-establish.
                debug!("Message from node: {} is not encrypted with known session keys. Requesting a WHOAREYOU packet", src_id);
                self.sessions.remove(&src_id);
                let event = ServiceEvent::WhoAreYouRequest {
                    src,
                    src_id,
                    auth_tag,
                };
                self.events.push_back(event);
                return Ok(());
            }
        };

        // Remove any associated request from pending_request
        if self
            .pending_requests
            .remove(&src, |req| req.id() == Some(message.id))
            .is_some()
        {
            trace!("Removing request id: {}", message.id);
        }

        // we have received a new message. Notify the behaviour.
        trace!("Message received: {} from: {}", message, src_id);
        let event = ServiceEvent::Message {
            src_id,
            src,
            message: Box::new(message),
        };
        self.events.push_back(event);

        // update the last_seen_socket and check if we need to promote the session to trusted
        session.set_last_seen_socket(src);

        // There are two possibilities a session could have been established. The latest message
        // matches the known ENR and upgrades the session to an established state, or, we were
        // awaiting a message to be decrypted with new session keys, this just arrived and we now
        // consider the session established. In both cases, we notify the user and flush the cached
        // messages.
        if (session.update_trusted() && session.trusted_established())
            | (session.trusted_established() && session_was_awaiting)
        {
            trace!("Session has been updated to ESTABLISHED. Node: {}", src_id);
            // session has been established, notify the protocol
            self.events.push_back(ServiceEvent::Established(
                session.remote_enr().clone().expect("ENR exists"),
            ));
            // update the session timeout
            self.sessions
                .update_timeout(&src_id, self.config.session_timeout);
            let _ = self.flush_messages(src, &src_id);
        }

        Ok(())
    }


    /// Wrapper around `transport.send()` that adds all sent messages to the `pending_requests`. This
    /// builds a request adds a timeout and sends the request.
    async fn process_request(
        &mut self,
        node_address: NodeAddress,
        packet: Packet,
        message: Option<ProtocolMessage>,
    ) {
        // construct the request
        let request = PendingRequest::new(node_address.node_id, packet, message);
        self.send(node_address.socket_addr.clone(), request.packet.clone()).await;
        self.pending_requests.insert(node_address.socket_addr, request);
    }

    /// Sends a packet to the send handler to be encoded and sent.
    async fn send(dst: SocketAddr, packet: Packet) {
                let outbound_packet = OutboundPacket { dst, packet} );
                self.socket.send.send(outbound_packet).await;
    }
}
