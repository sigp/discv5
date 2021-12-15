//! Session and packet handling for the Discv5 Discovery service.
//!
//! The [`Handler`] is responsible for establishing and maintaining sessions with
//! connected/discovered nodes. Each node, identified by it's [`NodeId`] is associated with a
//! `Session`. This service drives the handshakes for establishing the sessions and associated
//! logic for sending/requesting initial connections/ENR's to/from unknown peers.
//!
//! The [`Handler`] also manages the timeouts for each request and reports back RPC failures,
//! and received messages. Messages are encrypted and decrypted using the
//! associated `Session` for each node.
//!
//! An ongoing established connection is abstractly represented by a `Session`. A node that provides an ENR with an
//! IP address/port that doesn't match the source, is considered invalid. A node that doesn't know
//! their external contactable addresses should set their ENR IP field to `None`.
//!
//! The Handler also routinely checks the timeouts for banned nodes and removes them from the
//! banned list once their ban expires.
//!
//! # Usage
//!
//! Interacting with a handler is done via channels. A Handler is spawned using the [`Handler::spawn`]
//! function. This returns an exit channel, a sending and receiving channel respectively. If the
//! exit channel is dropped or fired, the handler task gets shutdown.
//!
//! Requests to the handler can be made via the sending channel using a [`HandlerRequest`].
//! Responses come by the receiving channel in the form of a [`HandlerResponse`].
use crate::{
    config::Discv5Config,
    discv5::PERMIT_BAN_LIST,
    error::{Discv5Error, RequestError},
    packet::{ChallengeData, IdNonce, MessageNonce, Packet, PacketKind},
    rpc::{Message, Request, RequestBody, RequestId, Response, ResponseBody},
    socket,
    socket::{FilterConfig, Socket},
    Enr,
};
use enr::{CombinedKey, NodeId};
use futures::prelude::*;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    convert::TryFrom,
    default::Default,
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, trace, warn};

mod crypto;
mod hashmap_delay;
mod session;
mod tests;

pub use crate::node_info::{NodeAddress, NodeContact};

use crate::metrics::METRICS;

use crate::lru_time_cache::LruTimeCache;
use hashmap_delay::HashMapDelay;
use session::Session;

// The time interval to check banned peer timeouts and unban peers when the timeout has elapsed (in
// seconds).
const BANNED_NODES_CHECK: u64 = 300; // Check every 5 minutes.

/// Events sent to the handler to be executed.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
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
    Request(NodeContact, Box<Request>),

    /// Send a response to a received request to a particular node.
    ///
    /// The handler does not keep state of requests, so the application layer must send the
    /// response back to the `NodeAddress` from which the request was received.
    Response(NodeAddress, Box<Response>),

    /// A Random packet has been received and we have requested the application layer to inform
    /// us what the highest known ENR is for this node.
    /// The `WhoAreYouRef` is sent out in the `HandlerResponse::WhoAreYou` event and should
    /// be returned here to submit the application's response.
    WhoAreYou(WhoAreYouRef, Option<Enr>),
}

/// The outputs provided by the `Handler`.
#[derive(Debug, Clone, PartialEq)]
pub enum HandlerResponse {
    /// A session has been established with a node.
    ///
    /// A session is only considered established once we have received a signed ENR from the
    /// node and received messages from it's `SocketAddr` matching it's ENR fields.
    Established(Enr, ConnectionDirection),

    /// A Request has been received.
    Request(NodeAddress, Box<Request>),

    /// A Response has been received.
    Response(NodeAddress, Box<Response>),

    /// An unknown source has requested information from us. Return the reference with the known
    /// ENR of this node (if known). See the `HandlerRequest::WhoAreYou` variant.
    WhoAreYou(WhoAreYouRef),

    /// An RPC request failed.
    ///
    /// This returns the request ID and an error indicating why the request failed.
    RequestFailed(RequestId, RequestError),
}

/// How we connected to the node.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ConnectionDirection {
    /// The node contacted us.
    Incoming,
    /// We contacted the node.
    Outgoing,
}

/// A reference for the application layer to send back when the handler requests any known
/// ENR for the NodeContact.
#[derive(Debug, Clone, PartialEq)]
pub struct WhoAreYouRef(pub NodeAddress, MessageNonce);

#[derive(Debug)]
/// A Challenge (WHOAREYOU) object used to handle and send WHOAREYOU requests.
pub struct Challenge {
    /// The challenge data received from the node.
    data: ChallengeData,
    /// The remote's ENR if we know it. We can receive a challenge from an unknown node.
    remote_enr: Option<Enr>,
}

/// A request to a node that we are waiting for a response.
#[derive(Debug)]
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
    /// If we receive a Nodes Response with a total greater than 1. This keeps track of the
    /// remaining responses expected.
    remaining_responses: Option<u64>,
    /// Signifies if we are initiating the session with a random packet. This is only used to
    /// determine the connection direction of the session.
    initiating_session: bool,
}

impl RequestCall {
    fn new(
        contact: NodeContact,
        packet: Packet,
        request: Request,
        initiating_session: bool,
    ) -> Self {
        RequestCall {
            contact,
            packet,
            request,
            handshake_sent: false,
            retries: 1,
            remaining_responses: None,
            initiating_session,
        }
    }

    fn id(&self) -> &RequestId {
        &self.request.id
    }
}

/// Process to handle handshakes and sessions established from raw RPC communications between nodes.
pub struct Handler {
    /// Configuration for the discv5 service.
    request_retries: u8,
    /// The local node id to save unnecessary read locks on the ENR. The NodeID should not change
    /// during the operation of the server.
    node_id: NodeId,
    /// The local ENR.
    enr: Arc<RwLock<Enr>>,
    /// The key to sign the ENR and set up encrypted communication with peers.
    key: Arc<RwLock<CombinedKey>>,
    /// Pending raw requests. A list of raw messages we are awaiting a response from the remote.
    active_requests: HashMapDelay<NodeAddress, RequestCall>,
    // WHOAREYOU messages do not include the source node id. We therefore maintain another
    // mapping of active_requests via message_nonce. This allows us to match WHOAREYOU
    // requests with active requests sent.
    /// A mapping of all pending active raw requests message nonces to their NodeAddress.
    active_requests_nonce_mapping: HashMap<MessageNonce, NodeAddress>,
    /// The expected responses by SocketAddr which allows packets to pass the underlying filter.
    filter_expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
    /// Requests awaiting a handshake completion.
    pending_requests: HashMap<NodeAddress, Vec<(NodeContact, Request)>>,
    /// Currently in-progress handshakes with peers.
    active_challenges: LruTimeCache<NodeAddress, Challenge>,
    /// Established sessions with peers.
    sessions: LruTimeCache<NodeAddress, Session>,
    /// The channel that receives requests from the application layer.
    inbound_channel: mpsc::UnboundedReceiver<HandlerRequest>,
    /// The channel to send responses to the application layer.
    outbound_channel: mpsc::Sender<HandlerResponse>,
    /// The listening socket to filter out any attempted requests to self.
    listen_socket: SocketAddr,
    /// The discovery v5 UDP socket tasks.
    socket: Socket,
    /// Exit channel to shutdown the handler.
    exit: oneshot::Receiver<()>,
}

type HandlerReturn = (
    oneshot::Sender<()>,
    mpsc::UnboundedSender<HandlerRequest>,
    mpsc::Receiver<HandlerResponse>,
);
impl Handler {
    /// A new Session service which instantiates the UDP socket send/recv tasks.
    pub async fn spawn(
        enr: Arc<RwLock<Enr>>,
        key: Arc<RwLock<CombinedKey>>,
        listen_socket: SocketAddr,
        config: Discv5Config,
    ) -> Result<HandlerReturn, std::io::Error> {
        let (exit_sender, exit) = oneshot::channel();
        // create the channels to send/receive messages from the application
        let (inbound_send, inbound_channel) = mpsc::unbounded_channel();
        let (outbound_channel, outbound_recv) = mpsc::channel(50);

        // Creates a SocketConfig to pass to the underlying UDP socket tasks.

        // Lets the underlying filter know that we are expecting a packet from this source.
        let filter_expected_responses = Arc::new(RwLock::new(HashMap::new()));

        // The local node id
        let node_id = enr.read().node_id();

        // enable the packet filter if required

        let filter_config = FilterConfig {
            enabled: config.enable_packet_filter,
            rate_limiter: config.filter_rate_limiter.clone(),
            max_nodes_per_ip: config.filter_max_nodes_per_ip,
            max_bans_per_ip: config.filter_max_bans_per_ip,
        };

        let socket_config = socket::SocketConfig {
            executor: config.executor.clone().expect("Executor must exist"),
            socket_addr: listen_socket,
            filter_config,
            local_node_id: node_id,
            expected_responses: filter_expected_responses.clone(),
            ban_duration: config.ban_duration,
        };

        // Attempt to bind to the socket before spinning up the send/recv tasks.
        let socket = socket::Socket::new_socket(&socket_config.socket_addr).await?;

        config
            .executor
            .clone()
            .expect("Executor must be present")
            .spawn(Box::pin(async move {
                let socket = match socket::Socket::new(socket, socket_config) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Could not bind UDP socket. {}", e);
                        return;
                    }
                };

                let mut handler = Handler {
                    request_retries: config.request_retries,
                    node_id,
                    enr,
                    key,
                    active_requests: HashMapDelay::new(config.request_timeout),
                    active_requests_nonce_mapping: HashMap::new(),
                    pending_requests: HashMap::new(),
                    filter_expected_responses,
                    sessions: LruTimeCache::new(
                        config.session_timeout,
                        Some(config.session_cache_capacity),
                    ),
                    active_challenges: LruTimeCache::new(config.request_timeout * 2, None),
                    inbound_channel,
                    outbound_channel,
                    listen_socket,
                    socket,
                    exit,
                };
                debug!("Handler Starting");
                handler.start().await;
            }));

        Ok((exit_sender, inbound_send, outbound_recv))
    }

    /// The main execution loop for the handler.
    async fn start(&mut self) {
        let mut banned_nodes_check = tokio::time::interval(Duration::from_secs(BANNED_NODES_CHECK));

        loop {
            tokio::select! {
                Some(handler_request) = self.inbound_channel.recv() => {
                    match handler_request {
                        HandlerRequest::Request(contact, request) => {
                           let id = request.id.clone();
                           if let Err(request_error) =  self.send_request(contact, *request).await {
                               // If the sending failed report to the application
                               let _ = self.outbound_channel.send(HandlerResponse::RequestFailed(id, request_error)).await;
                           }
                        }
                        HandlerRequest::Response(dst, response) => self.send_response(dst, *response).await,
                        HandlerRequest::WhoAreYou(wru_ref, enr) => self.send_challenge(wru_ref, enr).await,
                    }
                }
                Some(inbound_packet) = self.socket.recv.recv() => {
                    self.process_inbound_packet(inbound_packet).await;
                }
                Some(Ok((node_address, pending_request))) = self.active_requests.next() => {
                    self.handle_request_timeout(node_address, pending_request).await;
                }
                _ = banned_nodes_check.tick() => self.unban_nodes_check(), // Unban nodes that are past the timeout
                _ = &mut self.exit => {
                    return;
                }
            }
        }
    }

    /// Processes an inbound decoded packet.
    async fn process_inbound_packet(&mut self, inbound_packet: socket::InboundPacket) {
        let message_nonce = inbound_packet.header.message_nonce;
        match inbound_packet.header.kind {
            PacketKind::WhoAreYou { enr_seq, .. } => {
                let challenge_data =
                    ChallengeData::try_from(inbound_packet.authenticated_data.as_slice())
                        .expect("Must be correct size");
                self.handle_challenge(
                    inbound_packet.src_address,
                    message_nonce,
                    enr_seq,
                    challenge_data,
                )
                .await
            }
            PacketKind::Handshake {
                src_id,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            } => {
                let node_address = NodeAddress {
                    socket_addr: inbound_packet.src_address,
                    node_id: src_id,
                };
                self.handle_auth_message(
                    node_address,
                    message_nonce,
                    &id_nonce_sig,
                    &ephem_pubkey,
                    enr_record,
                    &inbound_packet.message,
                    &inbound_packet.authenticated_data, // This is required for authenticated data in decryption.
                )
                .await
            }
            PacketKind::Message { src_id } => {
                let node_address = NodeAddress {
                    socket_addr: inbound_packet.src_address,
                    node_id: src_id,
                };
                self.handle_message(
                    node_address,
                    message_nonce,
                    &inbound_packet.message,
                    &inbound_packet.authenticated_data,
                )
                .await
            }
        }
    }

    fn remove_expected_response(&mut self, socket_addr: SocketAddr) {
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.filter_expected_responses.write().entry(socket_addr)
        {
            let count = entry.get_mut();
            *count = count.saturating_sub(1);
            if count == &0 {
                entry.remove();
            }
        }
    }

    fn add_expected_response(&mut self, socket_addr: SocketAddr) {
        *self
            .filter_expected_responses
            .write()
            .entry(socket_addr)
            .or_default() += 1;
    }

    /// A request has timed out.
    async fn handle_request_timeout(
        &mut self,
        node_address: NodeAddress,
        mut request_call: RequestCall,
    ) {
        if request_call.retries >= self.request_retries {
            trace!("Request timed out with {}", node_address);
            // Remove the request from the awaiting packet_filter
            // Remove the associated nonce mapping.
            self.active_requests_nonce_mapping
                .remove(request_call.packet.message_nonce());
            self.remove_expected_response(node_address.socket_addr);
            // The request has timed out. We keep any established session for future use.
            self.fail_request(request_call, RequestError::Timeout, false)
                .await;
        } else {
            // increment the request retry count and restart the timeout
            trace!(
                "Resending message: {} to {}",
                request_call.request,
                node_address
            );
            self.send(node_address.clone(), request_call.packet.clone())
                .await;
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

        if node_address.socket_addr == self.listen_socket {
            debug!("Filtered request to self");
            return Err(RequestError::SelfRequest);
        }

        // If there is already an active request for this node, add to pending requests
        if self.active_requests.get(&node_address).is_some() {
            trace!("Request queued for node: {}", node_address);
            self.pending_requests
                .entry(node_address)
                .or_insert_with(Vec::new)
                .push((contact, request));
            return Ok(());
        }

        let (packet, initiating_session) = {
            if let Some(session) = self.sessions.get_mut(&node_address) {
                // Encrypt the message and send
                let packet = session
                    .encrypt_message(self.node_id, &request.clone().encode())
                    .map_err(|e| RequestError::EncryptionFailed(format!("{:?}", e)))?;
                (packet, false)
            } else {
                // No session exists, start a new handshake
                trace!(
                    "Starting session. Sending random packet to: {}",
                    node_address
                );
                let packet =
                    Packet::new_random(&self.node_id).map_err(RequestError::EntropyFailure)?;
                // We are initiating a new session
                (packet, true)
            }
        };

        let call = RequestCall::new(contact, packet.clone(), request, initiating_session);
        // let the filter know we are expecting a response
        self.add_expected_response(node_address.socket_addr);
        let nonce = *packet.message_nonce();
        self.send(node_address.clone(), packet).await;

        self.active_requests_nonce_mapping
            .insert(nonce, node_address.clone());
        self.active_requests.insert(node_address, call);
        Ok(())
    }

    /// Sends an RPC Response.
    async fn send_response(&mut self, node_address: NodeAddress, response: Response) {
        // Check for an established session
        if let Some(session) = self.sessions.get_mut(&node_address) {
            // Encrypt the message and send
            let packet = match session.encrypt_message(self.node_id, &response.encode()) {
                Ok(packet) => packet,
                Err(e) => {
                    warn!("Could not encrypt response: {:?}", e);
                    return;
                }
            };
            self.send(node_address, packet).await;
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
    async fn send_challenge(&mut self, wru_ref: WhoAreYouRef, remote_enr: Option<Enr>) {
        let node_address = wru_ref.0;
        let message_nonce = wru_ref.1;

        if self.active_challenges.peek(&node_address).is_some() {
            warn!("WHOAREYOU already sent. {}", node_address);
            return;
        }

        // Ignore this request if the session is already established
        if self.sessions.get(&node_address).is_some() {
            trace!(
                "Session already established. WHOAREYOU not sent to {}",
                node_address
            );
            return;
        }

        // It could be the case we have sent an ENR with an active request, however we consider
        // these independent as this is in response to an unknown packet. If the ENR it not in our
        // table (remote_enr is None) then we re-request the ENR to keep the session up to date.

        // send the challenge
        let enr_seq = remote_enr.clone().map_or_else(|| 0, |enr| enr.seq());
        let id_nonce: IdNonce = rand::random();
        let packet = Packet::new_whoareyou(message_nonce, id_nonce, enr_seq);
        let challenge_data = ChallengeData::try_from(packet.authenticated_data().as_slice())
            .expect("Must be the correct challenge size");
        debug!("Sending WHOAREYOU to {}", node_address);
        self.send(node_address.clone(), packet).await;
        self.active_challenges.insert(
            node_address,
            Challenge {
                data: challenge_data,
                remote_enr,
            },
        );
    }

    /* Packet Handling */

    /// Handles a WHOAREYOU packet that was received from the network.
    async fn handle_challenge(
        &mut self,
        src_address: SocketAddr,
        request_nonce: MessageNonce,
        enr_seq: u64,
        challenge_data: ChallengeData,
    ) {
        // Check that this challenge matches a known active request.
        // If this message passes all the requisite checks, a request call is returned.
        let mut request_call = {
            // Check for an active request
            let node_address = match self.active_requests_nonce_mapping.remove(&request_nonce) {
                Some(addr) => addr,
                None => {
                    trace!("Received a WHOAREYOU packet that references an unknown or expired request. Source {}, message_nonce {}", src_address, hex::encode(request_nonce));
                    return;
                }
            };

            // Verify that the src_addresses match
            if node_address.socket_addr != src_address {
                trace!("Received a WHOAREYOU packet for a message with a non-expected source. Source {}, expected_source: {} message_nonce {}", src_address, node_address.socket_addr, hex::encode(request_nonce));
                // add the mapping back
                self.active_requests_nonce_mapping
                    .insert(request_nonce, node_address);
                return;
            }

            // Obtain the request from the mapping. This must exist, otherwise there is a
            // serious coding error. The active_requests_nonce_mapping and active_requests
            // mappings should be 1 to 1.

            match self.active_requests.remove(&node_address) {
                Some(request_call) => request_call,
                None => {
                    error!("Active request mappings are not in sync. Message_id {}, node_address {} doesn't exist in active request mapping", hex::encode(request_nonce), node_address);
                    // NOTE: Both mappings are removed in this case.
                    return;
                }
            }
        };

        // double check the message nonces match
        if request_call.packet.message_nonce() != &request_nonce {
            // This could theoretically happen if a peer uses the same node id across
            // different connections.
            warn!("Received a WHOAREYOU from a non expected source. Source: {}, message_nonce {} , expected_nonce: {}", request_call.contact, hex::encode(request_call.packet.message_nonce()), hex::encode(request_nonce));
            // NOTE: Both mappings are removed in this case.
            return;
        }

        trace!(
            "Received a WHOAREYOU packet response. Source: {}",
            request_call.contact
        );

        // We do not allow multiple WHOAREYOU packets for a single challenge request. If we have
        // already sent a WHOAREYOU ourselves, we drop sessions who send us a WHOAREYOU in
        // response.
        if request_call.handshake_sent {
            warn!(
                "Authentication response already sent. Dropping session. Node: {}",
                request_call.contact
            );
            self.fail_request(request_call, RequestError::InvalidRemotePacket, true)
                .await;
            return;
        }

        // Encrypt the message with an auth header and respond

        // First if a new version of our ENR is requested, obtain it for the header
        let updated_enr = if enr_seq < self.enr.read().seq() {
            Some(self.enr.read().clone())
        } else {
            None
        };

        // Generate a new session and authentication packet
        let (auth_packet, mut session) = match Session::encrypt_with_header(
            &request_call.contact,
            self.key.clone(),
            updated_enr,
            &self.node_id,
            &challenge_data,
            &(request_call.request.clone().encode()),
        ) {
            Ok(v) => v,
            Err(e) => {
                error!("Could not generate a session. Error: {:?}", e);
                self.fail_request(request_call, RequestError::InvalidRemotePacket, true)
                    .await;
                return;
            }
        };

        // There are two quirks with an established session at this point.
        // 1. We may not know the ENR if we dialed this node with a NodeContact::Raw. In this case
        //    we need to set up a request to find the ENR and wait for a response before we
        //    officially call this node established.
        // 2. The challenge here could be to an already established session. If so, we need to
        //    update the existing session to attempt to decrypt future messages with the new keys
        //    and update the keys internally upon successful decryption.
        //
        // We handle both of these cases here.

        // Check if we know the ENR, if not request it and flag the session as awaiting an ENR.
        //
        // All sent requests must have an associated node_id. Therefore the following
        // must not panic.
        let node_address = request_call
            .contact
            .node_address()
            .expect("All sent requests must have a node address");
        match request_call.contact.clone() {
            NodeContact::Enr(enr) => {
                // NOTE: Here we decide if the session is outgoing or ingoing. The condition for an
                // outgoing session is that we originally sent a RANDOM packet (signifying we did
                // not have a session for a request) and the packet is not a PING (we are not
                // trying to update an old session that may have expired.
                let connection_direction = {
                    match (&request_call.initiating_session, &request_call.request.body) {
                        (true, RequestBody::Ping { .. }) => ConnectionDirection::Incoming,
                        (true, _) => ConnectionDirection::Outgoing,
                        (false, _) => ConnectionDirection::Incoming,
                    }
                };

                // We already know the ENR. Send the handshake response packet
                trace!("Sending Authentication response to node: {}", node_address);
                request_call.packet = auth_packet.clone();
                request_call.handshake_sent = true;
                request_call.initiating_session = false;
                // Reinsert the request_call
                self.insert_active_request(request_call);
                // Send the actual packet to the send task.
                self.send(node_address.clone(), auth_packet).await;

                // Notify the application that the session has been established
                self.outbound_channel
                    .send(HandlerResponse::Established(*enr, connection_direction))
                    .await
                    .unwrap_or_else(|e| warn!("Error with sending channel: {}", e));
            }
            NodeContact::Raw { .. } => {
                // Don't know the ENR. Establish the session, but request an ENR also

                // Send the Auth response
                let contact = request_call.contact.clone();
                trace!(
                    "Sending Authentication response to node: {}",
                    request_call
                        .contact
                        .node_address()
                        .expect("Sanitized contact")
                );
                request_call.packet = auth_packet.clone();
                request_call.handshake_sent = true;
                // Reinsert the request_call
                self.insert_active_request(request_call);
                self.send(node_address.clone(), auth_packet).await;

                let id = RequestId::random();
                let request = Request {
                    id: id.clone(),
                    body: RequestBody::FindNode { distances: vec![0] },
                };

                session.awaiting_enr = Some(id);
                let _ = self.send_request(contact, request).await;
            }
        }
        self.new_session(node_address, session);
    }

    /// Verifies a Node ENR to it's observed address. If it fails, any associated session is also
    /// considered failed. If it succeeds, we notify the application.
    fn verify_enr(&self, enr: &Enr, node_address: &NodeAddress) -> bool {
        // If the ENR does not match the observed IP addresses, we consider the Session
        // failed.
        enr.node_id() == node_address.node_id
            && (enr.udp_socket().is_none() || enr.udp_socket() == Some(node_address.socket_addr))
    }

    /// Handle a message that contains an authentication header.
    #[allow(clippy::too_many_arguments)]
    async fn handle_auth_message(
        &mut self,
        node_address: NodeAddress,
        message_nonce: MessageNonce,
        id_nonce_sig: &[u8],
        ephem_pubkey: &[u8],
        enr_record: Option<Enr>,
        message: &[u8],
        authenticated_data: &[u8],
    ) {
        // Needs to match an outgoing challenge packet (so we have the required nonce to be signed). If it doesn't we drop the packet.
        // This will lead to future outgoing challenges if they proceed to send further encrypted
        // packets.
        trace!(
            "Received an Authentication header message from: {}",
            node_address
        );

        if let Some(challenge) = self.active_challenges.remove(&node_address) {
            match Session::establish_from_challenge(
                self.key.clone(),
                &self.node_id,
                &node_address.node_id,
                challenge,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            ) {
                Ok((session, enr)) => {
                    // Receiving an AuthResponse must give us an up-to-date view of the node ENR.
                    // Verify the ENR is valid
                    if self.verify_enr(&enr, &node_address) {
                        // Session is valid
                        // Notify the application
                        // The session established here are from WHOAREYOU packets that we sent.
                        // This occurs when a node established a connection with us.
                        let _ = self
                            .outbound_channel
                            .send(HandlerResponse::Established(
                                enr,
                                ConnectionDirection::Incoming,
                            ))
                            .await;
                        self.new_session(node_address.clone(), session);
                        self.handle_message(
                            node_address,
                            message_nonce,
                            message,
                            authenticated_data,
                        )
                        .await;
                    } else {
                        // IP's or NodeAddress don't match. Drop the session.
                        warn!(
                            "Session has invalid ENR. Enr socket: {:?}, {}",
                            enr.udp_socket(),
                            node_address
                        );
                        self.fail_session(&node_address, RequestError::InvalidRemoteEnr, true)
                            .await;
                    }
                }
                Err(Discv5Error::InvalidChallengeSignature(challenge)) => {
                    warn!(
                        "Authentication header contained invalid signature. Ignoring packet from: {}",
                        node_address
                    );
                    // insert back the challenge
                    self.active_challenges.insert(node_address, challenge);
                }
                Err(e) => {
                    warn!(
                        "Invalid Authentication header. Dropping session. Error: {:?}",
                        e
                    );
                    self.fail_session(&node_address, RequestError::InvalidRemotePacket, true)
                        .await;
                }
            }
        } else {
            warn!(
                "Received an authenticated header without a matching WHOAREYOU request. {}",
                node_address
            );
        }
    }

    async fn send_next_request(&mut self, node_address: NodeAddress) {
        // ensure we are not over writing any existing requests

        if self.active_requests.get(&node_address).is_none() {
            if let std::collections::hash_map::Entry::Occupied(mut entry) =
                self.pending_requests.entry(node_address)
            {
                // If it exists, there must be a request here
                let request = entry.get_mut().remove(0);
                if entry.get().is_empty() {
                    entry.remove();
                }
                trace!("Sending next awaiting message. Node: {}", request.0);
                let _ = self.send_request(request.0, request.1).await;
            }
        }
    }

    /// Handle a standard message that does not contain an authentication header.
    #[allow(clippy::single_match)]
    async fn handle_message(
        &mut self,
        node_address: NodeAddress,
        message_nonce: MessageNonce,
        message: &[u8],
        authenticated_data: &[u8],
    ) {
        // check if we have an available session
        if let Some(session) = self.sessions.get_mut(&node_address) {
            // attempt to decrypt and process the message.
            let message = match session.decrypt_message(message_nonce, message, authenticated_data)
            {
                Ok(m) => match Message::decode(&m) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to decode message. Error: {:?}, {}", e, node_address);
                        return;
                    }
                },
                Err(e) => {
                    // We have a session, but the message could not be decrypted. It is likely the node
                    // sending this message has dropped their session. In this case, this message is a
                    // Random packet and we should reply with a WHOAREYOU.
                    // This means we need to drop the current session and re-establish.
                    trace!("Decryption failed. Error {}", e);
                    debug!(
                        "Message from node: {} is not encrypted with known session keys.",
                        node_address
                    );
                    self.fail_session(&node_address, RequestError::InvalidRemotePacket, true)
                        .await;
                    // If we haven't already sent a WhoAreYou,
                    // spawn a WHOAREYOU event to check for highest known ENR
                    // Update the cache time and remove expired entries.
                    if self.active_challenges.peek(&node_address).is_none() {
                        let whoareyou_ref = WhoAreYouRef(node_address, message_nonce);
                        let _ = self
                            .outbound_channel
                            .send(HandlerResponse::WhoAreYou(whoareyou_ref))
                            .await;
                    } else {
                        trace!("WHOAREYOU packet already sent: {}", node_address);
                    }
                    return;
                }
            };

            trace!("Received message from: {}", node_address);

            // Remove any associated request from pending_request
            match message {
                Message::Request(request) => {
                    // report the request to the application
                    let _ = self
                        .outbound_channel
                        .send(HandlerResponse::Request(node_address, Box::new(request)))
                        .await;
                }
                Message::Response(response) => {
                    // Sessions could be awaiting an ENR response. Check if this response matches
                    // these
                    if let Some(request_id) = session.awaiting_enr.as_ref() {
                        if &response.id == request_id {
                            session.awaiting_enr = None;
                            match response.body {
                                ResponseBody::Nodes { mut nodes, .. } => {
                                    // Received the requested ENR
                                    if let Some(enr) = nodes.pop() {
                                        if self.verify_enr(&enr, &node_address) {
                                            // Notify the application
                                            // This can occur when we try to dial a node without an
                                            // ENR. In this case we have attempted to establish the
                                            // connection, so this is an outgoing connection.
                                            let _ = self
                                                .outbound_channel
                                                .send(HandlerResponse::Established(
                                                    enr,
                                                    ConnectionDirection::Outgoing,
                                                ))
                                                .await;
                                            return;
                                        }
                                    }
                                }
                                _ => {}
                            }
                            debug!("Session failed invalid ENR response");
                            self.fail_session(&node_address, RequestError::InvalidRemoteEnr, true)
                                .await;
                            return;
                        }
                    }
                    // Handle standard responses
                    self.handle_response(node_address, response).await;
                }
            }
        } else {
            // no session exists
            trace!("Received a message without a session. {}", node_address);
            trace!("Requesting a WHOAREYOU packet to be sent.");
            // spawn a WHOAREYOU event to check for highest known ENR
            let whoareyou_ref = WhoAreYouRef(node_address, message_nonce);
            let _ = self
                .outbound_channel
                .send(HandlerResponse::WhoAreYou(whoareyou_ref))
                .await;
        }
    }

    /// Handles a response to a request. Re-inserts the request call if the response is a multiple
    /// Nodes response.
    async fn handle_response(&mut self, node_address: NodeAddress, response: Response) {
        // Find a matching request, if any
        if let Some(mut request_call) = self.active_requests.remove(&node_address) {
            if request_call.id() != &response.id {
                trace!(
                    "Received an RPC Response to an unknown request. Likely late response. {}",
                    node_address
                );
                // add the request back and reset the timer
                self.active_requests.insert(node_address, request_call);
                return;
            }

            // The response matches a request

            // Check to see if this is a Nodes response, in which case we may require to wait for
            // extra responses
            if let ResponseBody::Nodes { total, .. } = response.body {
                if total > 1 {
                    // This is a multi-response Nodes response
                    if let Some(remaining_responses) = request_call.remaining_responses.as_mut() {
                        *remaining_responses -= 1;
                        if remaining_responses != &0 {
                            // more responses remaining, add back the request and send the response
                            // add back the request and send the response
                            self.active_requests
                                .insert(node_address.clone(), request_call);
                            let _ = self
                                .outbound_channel
                                .send(HandlerResponse::Response(node_address, Box::new(response)))
                                .await;
                            return;
                        }
                    } else {
                        // This is the first instance
                        request_call.remaining_responses = Some(total - 1);
                        // add back the request and send the response
                        self.active_requests
                            .insert(node_address.clone(), request_call);
                        let _ = self
                            .outbound_channel
                            .send(HandlerResponse::Response(node_address, Box::new(response)))
                            .await;
                        return;
                    }
                }
            }

            // Remove the associated nonce mapping.
            self.active_requests_nonce_mapping
                .remove(request_call.packet.message_nonce());
            // Remove the expected response
            self.remove_expected_response(node_address.socket_addr);

            // The request matches report the response
            let _ = self
                .outbound_channel
                .send(HandlerResponse::Response(
                    node_address.clone(),
                    Box::new(response),
                ))
                .await;
            self.send_next_request(node_address).await;
        } else {
            // This is likely a late response and we have already failed the request. These get
            // dropped here.
            trace!("Late response from node: {}", node_address);
        }
    }

    /// Inserts a request and associated auth_tag mapping.
    fn insert_active_request(&mut self, request_call: RequestCall) {
        let node_address = request_call
            .contact
            .node_address()
            .expect("Can only add requests with a valid destination");
        // adds the mapping of message nonce to node address
        self.active_requests_nonce_mapping
            .insert(*request_call.packet.message_nonce(), node_address.clone());
        self.active_requests.insert(node_address, request_call);
    }

    fn new_session(&mut self, node_address: NodeAddress, session: Session) {
        if let Some(current_session) = self.sessions.get_mut(&node_address) {
            current_session.update(session);
        } else {
            self.sessions.insert(node_address, session);
            METRICS
                .active_sessions
                .store(self.sessions.len(), Ordering::Relaxed);
        }
    }

    /// A request has failed.
    async fn fail_request(
        &mut self,
        request_call: RequestCall,
        error: RequestError,
        remove_session: bool,
    ) {
        // The Request has expired, remove the session.
        // Remove the associated nonce mapping.
        self.active_requests_nonce_mapping
            .remove(request_call.packet.message_nonce());
        // Fail the current request
        let request_id = request_call.request.id;
        let _ = self
            .outbound_channel
            .send(HandlerResponse::RequestFailed(request_id, error.clone()))
            .await;

        let node_address = request_call
            .contact
            .node_address()
            .expect("All Request calls have been sanitized");
        self.fail_session(&node_address, error, remove_session)
            .await;
    }

    /// Removes a session and updates associated metrics and fields.
    async fn fail_session(
        &mut self,
        node_address: &NodeAddress,
        error: RequestError,
        remove_session: bool,
    ) {
        if remove_session {
            self.sessions.remove(node_address);
            METRICS
                .active_sessions
                .store(self.sessions.len(), Ordering::Relaxed);
        }
        for request in self
            .pending_requests
            .remove(node_address)
            .unwrap_or_else(Vec::new)
        {
            let _ = self
                .outbound_channel
                .send(HandlerResponse::RequestFailed(request.1.id, error.clone()))
                .await;
        }
    }

    /// Sends a packet to the send handler to be encoded and sent.
    async fn send(&mut self, node_address: NodeAddress, packet: Packet) {
        let outbound_packet = socket::OutboundPacket {
            node_address,
            packet,
        };
        let _ = self.socket.send.send(outbound_packet).await;
    }

    /// Check if any banned nodes have served their time and unban them.
    fn unban_nodes_check(&self) {
        PERMIT_BAN_LIST
            .write()
            .ban_ips
            .retain(|_, time| time.is_none() || Some(Instant::now()) < *time);
        PERMIT_BAN_LIST
            .write()
            .ban_nodes
            .retain(|_, time| time.is_none() || Some(Instant::now()) < *time);
    }
}
