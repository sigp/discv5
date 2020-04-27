//! Session management for the Discv5 Discovery service.
//!
//! The `SessionService` is responsible for establishing and maintaining sessions with
//! connected/discovered nodes. Each node, identified by it's [`NodeId`] is associated with a
//! [`Session`]. This service drives the handshakes for establishing the sessions and associated
//! logic for sending/requesting initial connections/ENR's from unknown peers.
//!
//! The `SessionService` also manages the timeouts for each request and reports back RPC failures,
//! session timeouts and received messages. Messages are encrypted and decrypted using the
//! associated `Session` for each node.
//!
//! An ongoing connection is managed by the `Session` struct. A node that provides and ENR with an
//! IP address/port that doesn't match the source, is considered untrusted. Once the IP is updated
//! to match the source, the `Session` is promoted to an established state. RPC requests are not sent
//! to untrusted Sessions, only responses.
//TODO: Document the event structure and WHOAREYOU requests to the protocol layer.
//TODO: Limit packets per node to avoid DOS/Spam.

use super::service::Discv5Service;
use crate::config::Discv5Config;
use crate::error::Discv5Error;
use crate::packet::{AuthHeader, AuthTag, Magic, Nonce, Packet, Tag, TAG_LENGTH};
use crate::rpc::ProtocolMessage;
use crate::session::Session;
use enr::{CombinedKey, Enr, EnrError, NodeId};
use futures::prelude::*;
use log::{debug, error, trace, warn};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::default::Default;
use std::net::SocketAddr;

mod tests;
mod timed_requests;
mod timed_sessions;

use timed_requests::TimedRequests;
use timed_sessions::TimedSessions;

pub struct SessionService {
    /// Queue of events produced by the session service.
    events: VecDeque<SessionEvent>,

    /// Configuration for the discv5 service.
    config: Discv5Config,

    /// The local ENR.
    enr: Enr<CombinedKey>,

    /// The key to sign the ENR and set up encrypted communication with peers.
    key: enr::CombinedKey,

    /// Pending raw requests. A list of raw messages we are awaiting a response from the remote.
    /// These are indexed by SocketAddr as WHOAREYOU messages do not return a source node id to
    /// match against.
    pending_requests: TimedRequests,

    /// Pending messages. Messages awaiting to be sent, once a handshake has been established.
    pending_messages: HashMap<NodeId, Vec<ProtocolMessage>>,

    /// Sessions that have been created for each node id. These can be established or
    /// awaiting response from remote nodes.
    //TODO: Limit number of sessions
    sessions: TimedSessions,

    /// The discovery v5 UDP service.
    service: Discv5Service,
}

impl SessionService {
    /* Public Functions */

    /// A new Session service which instantiates the UDP socket.
    pub fn new(
        enr: Enr<CombinedKey>,
        key: enr::CombinedKey,
        listen_socket: SocketAddr,
        config: Discv5Config,
    ) -> Result<Self, Discv5Error> {
        // generates the WHOAREYOU magic packet for the local node-id
        let magic = {
            let mut hasher = Sha256::new();
            hasher.input(enr.node_id().raw());
            hasher.input(b"WHOAREYOU");
            let mut magic: Magic = Default::default();
            magic.copy_from_slice(&hasher.result());
            magic
        };

        Ok(SessionService {
            events: VecDeque::new(),
            enr,
            key,
            pending_requests: TimedRequests::new(config.request_timeout),
            pending_messages: HashMap::default(),
            sessions: TimedSessions::new(config.session_establish_timeout),
            service: Discv5Service::new(listen_socket, magic)
                .map_err(|e| Discv5Error::Error(format!("{:?}", e)))?,
            config,
        })
    }

    /// The local ENR of the service.
    pub fn enr(&self) -> &Enr<CombinedKey> {
        &self.enr
    }

    /// Generic function to modify a field in the local ENR.
    pub fn enr_insert(&mut self, key: &str, value: Vec<u8>) -> Result<Option<Vec<u8>>, EnrError> {
        self.enr.insert(key, value, &self.key)
    }

    /// Updates the local ENR `SocketAddr` for either the TCP or UDP port.
    pub fn update_local_enr_socket(
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
    pub fn update_enr(&mut self, enr: Enr<CombinedKey>) {
        if let Some(session) = self.sessions.get_mut(&enr.node_id()) {
            // if an ENR is updated to an address that was not the last seen address of the
            // session, we demote the session to untrusted.
            if session.update_enr(enr.clone()) {
                // A session have been promoted to established. Noftify the protocol
                self.events.push_back(SessionEvent::Established(enr));
            }
        }
    }

    /// Sends a `ProtocolMessage` request to a known ENR. It is possible to send requests to IP
    /// addresses not related to the ENR.
    // To update an ENR for an unknown node, we request a FINDNODE with distance 0 to the IP
    // address that we know of.
    pub fn send_request(
        &mut self,
        dst_enr: &Enr<CombinedKey>,
        message: ProtocolMessage,
    ) -> Result<(), Discv5Error> {
        // check for an established session
        let dst_id = dst_enr.node_id();

        let dst = dst_enr.udp_socket().ok_or_else(|| {
            warn!(
                "Could not send message. ENR doesn't contain an IP and UDP port: {}",
                dst_enr
            );
            Discv5Error::InvalidEnr
        })?;

        let session = match self.sessions.get(&dst_id) {
            Some(s) if s.trusted_established() => s,
            Some(_) => {
                // we are currently establishing a connection, add to pending messages
                debug!("Session is being established, request failed");
                // Note: For the sake of request speed. We don't cache this message and await a
                // session to be established. The session could take a while to be established or
                // eventually fail. We prefer the request to fail quickly upfront.
                return Err(Discv5Error::InvalidEnr);
            }
            None => {
                debug!(
                    "No session established, sending a random packet to: {}",
                    dst_id
                );
                // cache message
                let msgs = self
                    .pending_messages
                    .entry(dst_id.clone())
                    .or_insert_with(Vec::new);
                msgs.push(message);

                // need to establish a new session, send a random packet
                let (session, packet) = Session::new_random(self.tag(&dst_id), dst_enr.clone());

                self.process_request(dst, dst_id.clone(), packet, None);
                self.sessions.insert(dst_id.clone(), session);
                return Ok(());
            }
        };

        // a session exists,
        // only send to trusted sessions (the ip's match the ENR)
        if !session.is_trusted() {
            debug!(
                "Tried to send a request to an untrusted node, ignoring. Node: {}",
                dst_id
            );
            return Err(Discv5Error::SessionNotEstablished);
        }

        // encrypt the message and send
        let packet = session
            .encrypt_message(self.tag(&dst_id), &message.clone().encode())
            .map_err(|e| {
                error!("Failed to encrypt message");
                e
            })?;

        self.process_request(dst, dst_id.clone(), packet, Some(message));

        Ok(())
    }

    /// Similar to `send_request` but for requests which an ENR may be unknown. A session is
    /// therefore assumed to be valid.
    // An example of this is requesting an ENR update from a NODE who's IP address is incorrect.
    // We send this request as a response to a ping. Assume a session is valid.
    pub fn send_request_unknown_enr(
        &mut self,
        dst: SocketAddr,
        dst_id: &NodeId,
        message: ProtocolMessage,
    ) -> Result<(), Discv5Error> {
        // session should be established
        let session = self.sessions.get(dst_id).ok_or_else(|| {
            warn!("Request without an ENR could not be sent, no session exists");
            Discv5Error::SessionNotEstablished
        })?;

        let packet = session
            .encrypt_message(self.tag(&dst_id), &message.clone().encode())
            .map_err(|e| {
                error!("Failed to encrypt message");
                e
            })?;

        self.process_request(dst, dst_id.clone(), packet, Some(message));
        Ok(())
    }

    /// Sends an RPC Response. This differs from send request as responses do not require a
    /// known ENR to send messages and session's should already be established.
    pub fn send_response(
        &mut self,
        dst: SocketAddr,
        dst_id: &NodeId,
        message: ProtocolMessage,
    ) -> Result<(), Discv5Error> {
        // session should be established
        let session = self.sessions.get(dst_id).ok_or_else(|| {
            warn!("Response could not be sent, no session is exists");
            Discv5Error::SessionNotEstablished
        })?;

        let packet = session
            .encrypt_message(self.tag(&dst_id), &message.clone().encode())
            .map_err(|e| {
                error!("Failed to encrypt message");
                e
            })?;

        // send the response
        // trace!("Sending Response: {:?} to {:?}", packet, dst);
        self.service.send(dst, packet);
        Ok(())
    }

    /// This is called in response to a SessionMessage::WhoAreYou event. The protocol finds the
    /// highest known ENR then calls this function to send a WHOAREYOU packet.
    pub fn send_whoareyou(
        &mut self,
        dst: SocketAddr,
        node_id: &NodeId,
        enr_seq: u64,
        remote_enr: Option<Enr<CombinedKey>>,
        auth_tag: AuthTag,
    ) {
        // If a WHOAREYOU is already sent or a session is already established, ignore this request.
        // However if a random packet was sent with a known ENR and this request has no known
        // ENR. Use the ENR of the previously established Session.
        let mut remote_enr = remote_enr;
        if let Some(prev_session) = self.sessions.get(node_id) {
            if prev_session.trusted_established() || prev_session.is_whoareyou_sent() {
                warn!("Session exists. WhoAreYou packet not sent");
                return;
            }
            if remote_enr.is_none() && prev_session.remote_enr().is_some() {
                remote_enr = prev_session.remote_enr().clone();
            }
        }

        debug!("Sending WHOAREYOU packet to: {}", node_id);
        let (session, packet) = Session::new_whoareyou(node_id, enr_seq, remote_enr, auth_tag);
        self.sessions.insert(node_id.clone(), session);
        self.process_request(dst, node_id.clone(), packet, None);
    }

    /* Internal Private Functions */

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

    /// Handles a WHOAREYOU packet that was received from the network.
    fn handle_whoareyou(
        &mut self,
        src: SocketAddr,
        token: AuthTag,
        id_nonce: Nonce,
        enr_seq: u64,
    ) -> Result<(), ()> {
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

        // Find the session associated with this WHOAREYOU
        let session = self.sessions.get_mut(&src_id).ok_or_else(|| {
            warn!("Received a WHOAREYOU packet without having an established session.")
        })?;

        // We should never receive a WHOAREYOU request, that matches an outgoing request AND have a
        // session that is in a WHOAREYOU_SENT state. If this is the case, drop the packet.
        if session.is_whoareyou_sent() {
            error!("Received a WHOAREYOU packet whilst in a WHOAREYOU session state. Source: {}, node: {}", src, src_id);
            return Ok(());
        }

        // Determine which message to send back. A WHOAREYOU could refer to the random packet
        // sent during an establishing a connection, or their session has expired on one of our
        // sent messages and we need to re-encrypt it.
        let message = {
            match req.packet {
                Packet::RandomPacket { .. } => {
                    // get the messages that are waiting for an established session
                    let messages = self
                        .pending_messages
                        .get_mut(&src_id)
                        .ok_or_else(|| warn!("No pending messages found for WHOAREYOU request."))?;

                    if messages.is_empty() {
                        // This could happen for an established connection and another peer (from the
                        // the same socketaddr) sends a WHOAREYOU packet
                        debug!("No pending messages found for WHOAREYOU request.");
                        return Err(());
                    }
                    // select the first message in the queue
                    messages.remove(0)
                }
                Packet::WhoAreYou { .. } => {
                    // a WhoAreYou packet was received in response to a WHOAREYOU.
                    warn!("A WHOAREYOU packet was received in response to a WHOAREYOU. Dropping packet and marking messages as failed");
                    return Err(());
                }
                _ => {
                    // re-send the original message
                    req.message
                        .expect("All non-random requests must have an unencrypted message")
                }
            }
        };

        // Update the session (this must be the socket that we sent the referenced request to)
        session.set_last_seen_socket(src);

        // Update the ENR record if necessary
        let updated_enr = if enr_seq < self.enr.seq() {
            Some(self.enr.clone())
        } else {
            None
        };

        // Generate session keys and encrypt the earliest packet with the authentication header
        let auth_packet = match session.encrypt_with_header(
            tag,
            &self.key,
            updated_enr,
            &self.enr.node_id(),
            &id_nonce,
            &message.clone().encode(),
        ) {
            Ok(p) => p,
            Err(e) => {
                // insert the message back into the pending queue
                self.pending_messages
                    .entry(src_id)
                    .or_insert_with(Vec::new)
                    .insert(0, message);
                error!("Could not generate a session. Error: {:?}", e);
                return Err(());
            }
        };

        // Send the response
        debug!("Sending Authentication response to node: {}", src_id);
        self.process_request(src, src_id.clone(), auth_packet, Some(message));

        // Flush the message cache
        let _ = self.flush_messages(src, &src_id);
        Ok(())
    }

    /// Handle a message that contains an authentication header.
    fn handle_auth_message(
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

        let session = self.sessions.get_mut(&src_id).ok_or_else(|| {
            warn!("Received an authenticated header without a known session. Dropping")
        })?;

        // check that this session is awaiting a response for a WHOAREYOU message
        if !session.is_whoareyou_sent() {
            warn!("Received an authenticated header without a known WHOAREYOU session. Dropping");
            return Err(());
        }

        let req = self
            .pending_requests
            .remove(&src, |req| {
                req.packet.is_whoareyou() && req.dst_id == src_id
            })
            .ok_or_else(|| {
                warn!("Received an authenticated header without a matching WHOAREYOU request");
            })?;

        // get the nonce
        let id_nonce = match req.packet {
            Packet::WhoAreYou { id_nonce, .. } => id_nonce,
            _ => unreachable!("Coding error if there is not a WHOAREYOU packet in this request"),
        };

        // update the sessions last seen socket
        session.set_last_seen_socket(src);

        // establish the session
        match session.establish_from_header(
            &self.key,
            &self.enr.node_id(),
            &src_id,
            id_nonce,
            &auth_header,
        ) {
            Ok(true) => {
                // the session is trusted, notify the protocol
                trace!("Session established with node: {}", src_id);
                // session has been established, notify the protocol
                self.events.push_back(SessionEvent::Established(
                    session
                        .remote_enr()
                        .clone()
                        .expect("ENR exists when awaiting a WHOAREYOU"),
                ));
                // flush messages awaiting an established session
                let _ = self.flush_messages(src, &src_id);
            }
            Ok(false) => {} // untrusted session, do not notify the protocol
            Err(e) => {
                warn!(
                    "Invalid Authentication header. Dropping session. Error: {:?}",
                    e
                );
                self.sessions.remove(&src_id);
                self.pending_messages.remove(&src_id);
                return Err(());
            }
        };

        // session has been established, update the timeout
        self.sessions
            .update_timeout(&src_id, self.config.session_timeout);

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
            let event = SessionEvent::WhoAreYouRequest {
                src,
                src_id: src_id.clone(),
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
            let event = SessionEvent::WhoAreYouRequest {
                src,
                src_id: src_id.clone(),
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
                let event = SessionEvent::WhoAreYouRequest {
                    src,
                    src_id: src_id.clone(),
                    auth_tag,
                };
                self.events.push_back(event);
                return Ok(());
            }
        };

        // Remove any associated request from pending_request
        if let Some(_) = self
            .pending_requests
            .remove(&src, |req| req.id() == Some(message.id))
        {
            trace!("Removing request id: {}", message.id);
        }

        // we have received a new message. Notify the behaviour.
        trace!("Message received: {} from: {}", message, src_id);
        let event = SessionEvent::Message {
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
            self.events.push_back(SessionEvent::Established(
                session.remote_enr().clone().expect("ENR exists"),
            ));
            let _ = self.flush_messages(src, &src_id);
        }

        Ok(())
    }

    /// Encrypts and sends any messages that were waiting for a session to be established.
    #[inline]
    fn flush_messages(&mut self, dst: SocketAddr, dst_id: &NodeId) -> Result<(), ()> {
        let mut requests_to_send = Vec::new();
        {
            // get the session for this id
            let session = match self.sessions.get(dst_id) {
                Some(s) if s.trusted_established() => s,
                _ => {
                    // no session
                    return Err(());
                }
            };

            let tag = self.tag(dst_id);

            let messages = self
                .pending_messages
                .remove(dst_id)
                .ok_or_else(|| trace!("No messages to send"))?;

            for msg in messages.into_iter() {
                let packet = session
                    .encrypt_message(tag, &msg.clone().encode())
                    .map_err(|e| warn!("Failed to encrypt message, Error: {:?}", e))?;
                requests_to_send.push((dst_id, packet, Some(msg)));
            }
        }

        for (dst_id, packet, message) in requests_to_send.into_iter() {
            debug!("Sending cached message");
            self.process_request(dst, dst_id.clone(), packet, message);
        }
        Ok(())
    }

    /// Wrapper around `service.send()` that adds all sent messages to the `pending_requests`. This
    /// builds a request adds a timeout and sends the request.
    #[inline]
    fn process_request(
        &mut self,
        dst: SocketAddr,
        dst_id: NodeId,
        packet: Packet,
        message: Option<ProtocolMessage>,
    ) {
        // construct the request
        let request = Request::new(dst_id, packet, message);
        self.service.send(dst, request.packet.clone());
        self.pending_requests.insert(dst.clone(), request);
    }

    /// The heartbeat which checks for timeouts and reports back failed RPC requests/sessions.
    fn check_timeouts(&mut self) {
        // remove expired requests/sessions
        // log pending request timeouts
        // TODO: Split into own task, to be called only when timeouts are required
        let sessions_ref = &mut self.sessions;
        let service_ref = &mut self.service;
        let pending_messages_ref = &mut self.pending_messages;
        let events_ref = &mut self.events;

        while let Ok(Async::Ready(Some((dst, mut request)))) = self.pending_requests.poll() {
            let node_id = request.dst_id.clone();
            if request.retries >= self.config.request_retries {
                // the RPC has expired
                // determine which kind of RPC has timed out
                match request.packet {
                    Packet::RandomPacket { .. } | Packet::WhoAreYou { .. } => {
                        // no response from peer, flush all pending messages
                        if let Some(pending_messages) = pending_messages_ref.remove(&node_id) {
                            for msg in pending_messages {
                                events_ref.push_back(SessionEvent::RequestFailed(node_id, msg.id));
                            }
                        }
                        // drop the session
                        debug!("Session couldn't be established with Node: {}", node_id);
                        sessions_ref.remove(&node_id);
                    }
                    Packet::AuthMessage { .. } | Packet::Message { .. } => {
                        debug!("Message timed out with node: {}", node_id);
                        events_ref.push_back(SessionEvent::RequestFailed(
                            node_id,
                            request.id().expect("Auth messages have an rpc id"),
                        ));
                    }
                }
            } else {
                // increment the request retry count and restart the timeout
                debug!(
                    "Resending message: {:?} to node: {}",
                    request.packet, node_id
                );
                service_ref.send(dst.clone(), request.packet.clone());
                request.retries += 1;
                self.pending_requests.insert(dst, request);
            }
        }

        // remove timed-out sessions - do not need to alert the protocol
        // Only drop a session if we are not expecting any responses.
        // TODO: Split into own task to be called only when a timeout expires
        // This is expensive, as it must loop through outgoing requests to check no request exists
        // for a given node id.
        let pending_requests_ref = &self.pending_requests;
        while let Ok(Async::Ready(Some((node_id, session)))) = self.sessions.poll() {
            if pending_requests_ref.exists(|req| req.dst_id == node_id) {
                // add the session back in with the current request timeout
                self.sessions
                    .insert_at(node_id, session, self.config.request_timeout);
            } else {
                // fail all pending requests for this node
                if let Some(pending_messages) = pending_messages_ref.remove(&node_id) {
                    for msg in pending_messages {
                        events_ref.push_back(SessionEvent::RequestFailed(node_id, msg.id));
                    }
                }
                debug!("Session timed out for node: {}", node_id);
            }
        }
    }

    pub fn poll(&mut self) -> Async<SessionEvent> {
        loop {
            // process any events if necessary
            if let Some(event) = self.events.pop_front() {
                return Async::Ready(event);
            }

            // poll the discv5 service
            match self.service.poll() {
                Async::Ready((src, packet)) => {
                    match packet {
                        Packet::WhoAreYou {
                            token,
                            id_nonce,
                            enr_seq,
                            ..
                        } => {
                            let _ = self.handle_whoareyou(src, token, id_nonce, enr_seq);
                        }
                        Packet::AuthMessage {
                            tag,
                            auth_header,
                            message,
                        } => {
                            let _ = self.handle_auth_message(src, tag, auth_header, &message);
                        }
                        Packet::Message {
                            tag,
                            auth_tag,
                            message,
                        } => {
                            let src_id = self.src_id(&tag);
                            let _ = self.handle_message(src, src_id, auth_tag, &message, tag);
                        }
                        Packet::RandomPacket { .. } => {} // this will not be decoded.
                    }
                }
                Async::NotReady => break,
            }
        }

        // check for timeouts
        self.check_timeouts();
        Async::NotReady
    }
}

#[derive(Debug)]
/// The output from polling the `SessionSerivce`.
pub enum SessionEvent {
    /// A session has been established with a node.
    Established(Enr<CombinedKey>),

    /// A message was received.
    Message {
        src_id: NodeId,
        src: SocketAddr,
        message: Box<ProtocolMessage>,
    },

    /// A WHOAREYOU packet needs to be sent. This requests the protocol layer to send back the
    /// highest known ENR.
    WhoAreYouRequest {
        src: SocketAddr,
        src_id: NodeId,
        auth_tag: AuthTag,
    },

    /// An RPC request failed. The parameters are NodeId and the RPC-ID associated with the
    /// request.
    RequestFailed(NodeId, u64),
}

#[derive(Debug)]
/// A request to a node that we are waiting for a response.
pub struct Request {
    /// The destination NodeId.
    pub dst_id: NodeId,

    /// The raw discv5 packet sent.
    pub packet: Packet,

    /// The unencrypted message. Required if need to re-encrypt and re-send.
    pub message: Option<ProtocolMessage>,

    /// The number of times this request has been re-sent.
    pub retries: u8,
}

impl Request {
    pub fn new(dst_id: NodeId, packet: Packet, message: Option<ProtocolMessage>) -> Self {
        Request {
            dst_id,
            packet,
            message,
            retries: 1,
        }
    }

    pub fn id(&self) -> Option<u64> {
        self.message.as_ref().map(|m| m.id)
    }
}
