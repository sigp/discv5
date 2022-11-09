//! The Discovery v5 protocol. See `lib.rs` for further details.
//!
//! Note: Discovered ENRs are not automatically added to the routing table. Only established
//! sessions get added, ensuring only valid ENRs are added. Manual additions can be made using the
//! `add_enr()` function.
//!
//! Response to queries return `PeerId`. Only the trusted (a session has been established with)
//! `PeerId`'s are returned, as ENRs for these `PeerId`'s are stored in the routing table and as
//! such should have an address to connect to. Untrusted `PeerId`'s can be obtained from the
//! `Service::Discovered` event, which is fired as peers get discovered.
//!
//! Note that although the ENR crate does support Ed25519 keys, these are currently not
//! supported as the ECDH procedure isn't specified in the specification. Therefore, only
//! secp256k1 keys are supported currently.

use self::{
    peer_votes::{Address, PeerVotes},
    query_info::{QueryInfo, QueryType},
};
use crate::{
    enr_nat::EnrNat,
    error::{RequestError, ResponseError},
    handler::{Handler, HandlerIn, HandlerOut, RoutingType},
    kbucket::{
        self, ConnectionDirection, ConnectionState, FailureReason, InsertResult, KBucketsTable,
        NodeStatus, UpdateResult, MAX_NODES_PER_BUCKET,
    },
    node_info::{NodeAddress, NodeContact, NonContactable},
    packet::MAX_PACKET_SIZE,
    query_pool::{
        FindNodeQueryConfig, PredicateQueryConfig, QueryId, QueryPool, QueryPoolState, TargetKey,
    },
    rpc, Discv5Config, Discv5Event, Enr,
};
use delay_map::HashSetDelay;
use enr::{CombinedKey, NodeId};
use fnv::FnvHashMap;
use futures::prelude::*;
use more_asserts::debug_unreachable;
use parking_lot::RwLock;
use rpc::*;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace, warn};

mod peer_votes;
mod query_info;
mod test;

/// The number of distances (buckets) we simultaneously request from each peer.
/// NOTE: This must not be larger than 127.
pub(crate) const DISTANCES_TO_REQUEST_PER_PEER: usize = 3;

/// Most NAT setups will keep a hole-punch connection alive if the UDP state table entry is
/// reset every 30 seconds, hence a node behind a NAT pings its peers at this interval.
const PING_INTERVAL_NAT: Duration = Duration::from_secs(60);

/// Peers behind a symmetric NAT are limited per kbucket as they can only be sent request not
/// passed in NODES responses to other peers.
const MAX_SYMMETRIC_NAT_PEERS_PER_KBUCKET: usize = 2;

/// Currently, a maximum of `DISTANCES_TO_REQUEST_PER_PEER * BUCKET_SIZE` peers
/// can be returned. Datagrams have a max size of 1280 and ENR's have a max size
/// of 300 bytes. Bucket sizes should be 16. Therefore, to return all required peers
/// there should be no more than `5 * DISTANCES_TO_REQUEST_PER_PEER` responses.
pub(crate) const MAX_NODES_RESPONSES: usize =
    (MAX_NODES_PER_BUCKET / 4 + 1) * DISTANCES_TO_REQUEST_PER_PEER;

/// Request type for Protocols using `TalkReq` message.
///
/// Automatically responds with an empty body on drop if
/// [`TalkRequest::respond`] is not called.
#[derive(Debug)]
pub struct TalkRequest {
    id: RequestId,
    node_address: NodeAddress,
    protocol: Vec<u8>,
    body: Vec<u8>,
    sender: Option<mpsc::UnboundedSender<HandlerIn>>,
}

impl Drop for TalkRequest {
    fn drop(&mut self) {
        let sender = match self.sender.take() {
            Some(s) => s,
            None => return,
        };

        let response = Response {
            id: self.id.clone(),
            body: ResponseBody::Talk { response: vec![] },
        };

        debug!("Sending empty TALK response to {}", self.node_address);
        if let Err(e) = sender.send(HandlerIn::Response(
            self.node_address.clone(),
            Box::new(response),
        )) {
            warn!("Failed to send empty talk response {}", e)
        }
    }
}

impl TalkRequest {
    pub fn id(&self) -> &RequestId {
        &self.id
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_address.node_id
    }

    pub fn protocol(&self) -> &[u8] {
        &self.protocol
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn respond(mut self, response: Vec<u8>) -> Result<(), ResponseError> {
        debug!("Sending TALK response to {}", self.node_address);

        let response = Response {
            id: self.id.clone(),
            body: ResponseBody::Talk { response },
        };

        self.sender
            .take()
            .unwrap()
            .send(HandlerIn::Response(
                self.node_address.clone(),
                Box::new(response),
            ))
            .map_err(|_| ResponseError::ChannelClosed)?;

        Ok(())
    }
}

/// The types of requests to send to the Discv5 service.
pub enum ServiceRequest {
    /// A request to start a query. There are two types of queries:
    /// - A FindNode Query - Searches for peers using a random target.
    /// - A Predicate Query - Searches for peers closest to a random target that match a specified
    /// predicate.
    StartQuery(QueryKind, oneshot::Sender<Vec<Enr>>),
    /// Find the ENR of a node given its multiaddr.
    FindEnr(NodeContact, oneshot::Sender<Result<Enr, RequestError>>),
    /// The TALK discv5 RPC function.
    Talk(
        NodeContact,
        Vec<u8>,
        Vec<u8>,
        oneshot::Sender<Result<Vec<u8>, RequestError>>,
    ),
    /// Sets up an event stream where the discv5 server will return various events such as
    /// discovered nodes as it traverses the DHT.
    RequestEventStream(oneshot::Sender<mpsc::Receiver<Discv5Event>>),
}

use crate::discv5::PERMIT_BAN_LIST;

pub struct Service {
    /// Configuration parameters.
    config: Discv5Config,

    /// The local ENR of the server.
    local_enr: Arc<RwLock<Enr>>,

    /// The key associated with the local ENR.
    enr_key: Arc<RwLock<CombinedKey>>,

    /// Storage of the ENR record for each node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Enr>>>,

    /// All the iterative queries we are currently performing.
    queries: QueryPool<QueryInfo, NodeId, Enr>,

    /// RPC requests that have been sent and are awaiting a response. Some requests are linked to
    /// query.
    active_requests: FnvHashMap<RequestId, ActiveRequest>,

    /// Keeps track of the number of responses received from a NODES response.
    active_nodes_responses: HashMap<NodeId, NodesResponse>,

    /// A record of votes nodes have made about our external IP address. This is used to determine
    /// the socket we should advertise in our ENR and if we are behind a NAT.
    peer_votes: PeerVotes,

    /// The channel to send messages to the handler.
    handler_send: mpsc::UnboundedSender<HandlerIn>,

    /// The channel to receive messages from the handler.
    handler_recv: mpsc::Receiver<HandlerOut>,

    /// The exit channel to shutdown the handler.
    handler_exit: Option<oneshot::Sender<()>>,

    /// The channel of messages sent by the controlling discv5 wrapper.
    discv5_recv: mpsc::Receiver<ServiceRequest>,

    /// The exit channel for the service.
    exit: oneshot::Receiver<()>,

    /// A queue of peers that require regular ping to check connectivity.
    peers_to_ping: HashSetDelay<NodeId>,

    /// A receiver/initiator peer that a hole-punch PING is sent to is stored to make sure only
    /// one relay is used at a time when trying to hole-punch a NAT and to keep track of
    /// connection direction in session establishment.
    hole_punch_pings: HashSet<NodeId>,

    /// A channel that the service emits events on.
    event_stream: Option<mpsc::Sender<Discv5Event>>,

    /// If this Discv5 instance is configured to allow peers behind symmetric NATs
    /// (peers that requests will be sent to but that will not be included in NODES
    /// responses to other peers) then connection dependent port mapping is stored.
    symmetric_nat_peers_ports: Option<HashMap<u64, HashMap<NodeId, u16>>>,

    /// A relay is stored for a peer added to the query so that incase it times out we can attempt
    /// to contact it via the NAT traversal protocol if supported.
    query_peer_relays: HashMap<NodeId, NodeId>,

    /// For RELAYREQUESTs for which this node is the rendezvous, the request ids of
    /// RELAYREQUESTs to receivers are mapped to the node address of the initiator and the request
    /// id of the request from the initiator so the RELAYRESPONSE can be returned to the
    /// initiator. The initiator could be a peer that is not in our kbuckets, e.g. a peer behind a
    /// symmetric NAT, hence the node address is stored.
    relayed_requests: HashMap<RequestId, RelayedRequest>,

    /// The ENRs of receivers for RELAYREQUESTs.
    receiver_enrs: HashMap<NodeId, Enr>,
}

/// When this node is a rendezvous, the id of the RELAYREQUEST from the initiator is
/// stored along with the node address of the initiator, so the RELAYRESPONSE from the
/// receiver can be re-packaged and relayed to the initiator.
struct RelayedRequest {
    initiator: NodeAddress,
    req_id_from_initiator: RequestId,
}

/// Active RPC request awaiting a response from the handler.
struct ActiveRequest {
    /// The address the request was sent to.
    pub contact: NodeContact,
    /// The request that was sent.
    pub request_body: RequestBody,
    /// The query ID if the request was related to a query.
    pub query_id: Option<QueryId>,
    /// Channel callback if this request was from a user level request.
    pub callback: Option<CallbackResponse>,
    /// If we have learnt about this peer in a FINDNODE query, we have a relay for it incase the
    /// query times out because this peer is behind an asymmetric NAT.
    pub relay: Option<NodeId>,
}

/// The kinds of responses we can send back to the discv5 layer.
pub enum CallbackResponse {
    /// A response to a requested ENR.
    Enr(oneshot::Sender<Result<Enr, RequestError>>),
    /// A response from a TALK request
    Talk(oneshot::Sender<Result<Vec<u8>, RequestError>>),
}

/// For multiple responses to a FindNodes request, this keeps track of the request count
/// and the nodes that have been received.
struct NodesResponse {
    /// The response count.
    count: usize,
    /// The filtered nodes that have been received.
    received_nodes: Vec<Enr>,
}

impl Default for NodesResponse {
    fn default() -> Self {
        NodesResponse {
            count: 1,
            received_nodes: Vec::new(),
        }
    }
}

impl Service {
    /// Builds the `Service` main struct.
    ///
    /// `local_enr` is the `ENR` representing the local node. This contains node identifying
    /// information, such
    /// as IP addresses and ports which we wish to broadcast to other nodes via this discovery
    /// mechanism.
    pub async fn spawn(
        local_enr: Arc<RwLock<Enr>>,
        enr_key: Arc<RwLock<CombinedKey>>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Enr>>>,
        config: Discv5Config,
        listen_socket: SocketAddr,
    ) -> Result<(oneshot::Sender<()>, mpsc::Sender<ServiceRequest>), std::io::Error> {
        // process behaviour-level configuration parameters
        let peer_votes = PeerVotes::new(
            config.enr_peer_update_min,
            config.enr_peer_update_min_nat,
            config.vote_duration,
            config.nat_symmetric_limit.map(|v| v > 0).unwrap_or(false),
        );

        // build the session service
        let (handler_exit, handler_send, handler_recv) = Handler::spawn(
            local_enr.clone(),
            enr_key.clone(),
            listen_socket,
            config.clone(),
        )
        .await?;

        // create the required channels
        let (discv5_send, discv5_recv) = mpsc::channel(30);
        let (exit_send, exit) = oneshot::channel();

        let symmetric_nat_peers_ports = config
            .nat_symmetric_limit
            .map(|v| v > 0)
            .unwrap_or(false)
            .then(HashMap::default);

        config
            .executor
            .clone()
            .expect("Executor must be present")
            .spawn(Box::pin(async move {
                let mut service = Service {
                    local_enr,
                    enr_key,
                    kbuckets,
                    queries: QueryPool::new(config.query_timeout),
                    active_requests: Default::default(),
                    active_nodes_responses: HashMap::new(),
                    peer_votes,
                    handler_send,
                    handler_recv,
                    handler_exit: Some(handler_exit),
                    peers_to_ping: HashSetDelay::new(config.ping_interval),
                    hole_punch_pings: Default::default(),
                    discv5_recv,
                    event_stream: None,
                    exit,
                    config: config.clone(),
                    query_peer_relays: Default::default(),
                    receiver_enrs: Default::default(),
                    symmetric_nat_peers_ports,
                    relayed_requests: Default::default(),
                };

                info!("Discv5 Service started");
                service.start().await;
            }));

        Ok((exit_send, discv5_send))
    }

    /// The main execution loop of the discv5 serviced.
    async fn start(&mut self) {
        info!("{:?}", self.config.ip_mode);
        loop {
            tokio::select! {
                _ = &mut self.exit => {
                    if let Some(exit) = self.handler_exit.take() {
                        let _ = exit.send(());
                        info!("Discv5 Service shutdown");
                    }
                    return;
                }
                Some(service_request) = self.discv5_recv.recv() => {
                    match service_request {
                        ServiceRequest::StartQuery(query, callback) => {
                            match query {
                                QueryKind::FindNode { target_node } => {
                                    self.start_findnode_query(target_node, callback);
                                }
                                QueryKind::Predicate { target_node, target_peer_no, predicate } => {
                                    self.start_predicate_query(target_node, target_peer_no, predicate, callback);
                                }
                            }
                        }
                        ServiceRequest::FindEnr(node_contact, callback) => {
                            self.request_enr(node_contact, Some(callback));
                        }
                        ServiceRequest::Talk(node_contact, protocol, request, callback) => {
                            self.talk_request(node_contact, protocol, request, callback);
                        }
                        ServiceRequest::RequestEventStream(callback) => {
                            // the channel size needs to be large to handle many discovered peers
                            // if we are reporting them on the event stream.
                            let channel_size = if self.config.report_discovered_peers { 100 } else { 30 };
                            let (event_stream, event_stream_recv) = mpsc::channel(channel_size);
                            self.event_stream = Some(event_stream);
                            if callback.send(event_stream_recv).is_err() {
                                error!("Failed to return the event stream channel");
                            }
                        }
                    }
                }
                Some(event) = self.handler_recv.recv() => {
                    match event {
                        HandlerOut::Established(routing_type) => {
                            match routing_type {
                                RoutingType::NoNatOrPortForward(enr, socket_addr, direction) => {
                                    self.send_event(Discv5Event::SessionEstablished(enr.clone(), socket_addr));

                                    let connection_direction = match self.hole_punch_pings.remove(&enr.node_id())
                                    {
                                        true => ConnectionDirection::Outgoing,
                                        _ => direction,
                                    };

                                    self.inject_session_established(enr, connection_direction);
                                }
                                RoutingType::AsymmetricNat(enr, socket_addr, direction) => {
                                    if self.local_enr.read().supports_nat() {
                                        info!("A new session has been established with a peer behind an asymmetric NAT. Peer: ENR: {}, socket: {}", enr, socket_addr);

                                        let connection_direction = match self.hole_punch_pings.remove(&enr.node_id())
                                        {
                                            true => ConnectionDirection::Outgoing,
                                            _ => direction,
                                        };

                                        self.inject_session_established_nat(enr, connection_direction);
                                    }
                                }
                                RoutingType::SymmetricNat(enr, socket_addr) => {
                                    if self.local_enr.read().supports_nat() {
                                        info!("A new session has been established with a peer behind a symmetric NAT. Peer: ENR: {}, socket: {}", enr, socket_addr);
                                        self.inject_session_established_nat_symmetric(enr, socket_addr.port());
                                    }
                                }
                            }
                        }
                        HandlerOut::Request(node_address, request) => {
                                self.handle_rpc_request(node_address, *request);
                            }
                        HandlerOut::Response(node_address, response) => {
                                self.handle_rpc_response(node_address, *response);
                            }
                        HandlerOut::WhoAreYou(whoareyou_ref) => {
                            // check what our latest known ENR is for this node.
                            if let Some(known_enr) = self.find_enr(&whoareyou_ref.0.node_id) {
                                if let Err(e) = self.handler_send.send(HandlerIn::WhoAreYou(whoareyou_ref, Some(known_enr))) {
                                    warn!("Failed to send whoareyou {}", e);
                                };
                            } else {
                                // do not know of this peer
                                debug!("NodeId unknown, requesting ENR. {}", whoareyou_ref.0);
                                if let Err(e) = self.handler_send.send(HandlerIn::WhoAreYou(whoareyou_ref, None)) {
                                    warn!("Failed to send who are you to unknown enr peer {}", e);
                                }
                            }
                        }
                        HandlerOut::RequestFailed(request_id, error) => {
                            match error {
                                RequestError::Timeout => {
                                    debug!("RPC Request timed out. id: {}", request_id);
                                }
                                RequestError::TimedOutHolePunchPing => {
                                    debug!("RPC Request PING to hole punch a NAT timed out. id: {}", request_id);
                                }
                                _ => {
                                    warn!("RPC Request failed: id: {}, error {:?}", request_id, error);
                                }
                            }
                            self.rpc_failure(request_id, error);
                        }
                    }
                }
                event = Service::bucket_maintenance_poll(&self.kbuckets) => {
                    self.send_event(event);
                }
                query_event = Service::query_event_poll(&mut self.queries) => {
                    match query_event {
                        QueryEvent::Waiting(query_id, node_id, request_body) => {
                            self.send_rpc_query(query_id, node_id, request_body);
                        }
                        // Note: Currently the distinction between a timed-out query and a finished
                        // query is superfluous, however it may be useful in future versions.
                        QueryEvent::Finished(query) | QueryEvent::TimedOut(query) => {
                            let id = query.id();
                            let mut result = query.into_result();
                            // obtain the ENRs for the resulting nodes
                            let mut found_enrs = Vec::new();
                            for node_id in result.closest_peers {
                                if let Some(position) = result.target.untrusted_enrs.iter().position(|enr| enr.node_id() == node_id) {
                                    let enr = result.target.untrusted_enrs.swap_remove(position);
                                    found_enrs.push(enr);
                                    self.query_peer_relays.remove(&node_id);
                                } else if let Some(enr) = self.find_enr(&node_id) {
                                    // look up from the routing table
                                    found_enrs.push(enr);
                                }
                                else {
                                    warn!("ENR not present in queries results");
                                }
                            }
                            if result.target.callback.send(found_enrs).is_err() {
                                warn!("Callback dropped for query {}. Results dropped", *id);
                            }
                        }
                    }
                }
                Some(Ok(node_id)) = self.peers_to_ping.next() => {
                    // If the node is in the routing table, Ping it and re-queue the node.
                    let key = kbucket::Key::from(node_id);
                    let enr = {
                        if let kbucket::Entry::Present(entry, _) = self.kbuckets.write().entry(&key) {
                        // The peer is in the routing table, ping it and re-queue the ping
                        self.peers_to_ping.insert(node_id);
                        Some(entry.value().clone())
                        } else { None }
                    };
                    if let Some(enr) = enr {
                        self.send_ping(&enr, false);
                    }
                }
            }
        }
    }

    /// Internal function that starts a query.
    fn start_findnode_query(&mut self, target_node: NodeId, callback: oneshot::Sender<Vec<Enr>>) {
        let mut target = QueryInfo {
            query_type: QueryType::FindNode(target_node),
            untrusted_enrs: Default::default(),
            distances_to_request: DISTANCES_TO_REQUEST_PER_PEER,
            callback,
        };

        let target_key: kbucket::Key<NodeId> = target.key();
        let mut known_closest_peers = Vec::new();
        {
            let mut kbuckets = self.kbuckets.write();
            for closest in kbuckets.closest_values(&target_key) {
                // Add the known ENRs to the untrusted list
                target.untrusted_enrs.push(closest.value);
                // Add the key to the list for the query
                known_closest_peers.push(closest.key);
            }
        }

        if known_closest_peers.is_empty() {
            warn!("No known_closest_peers found. Return empty result without sending query.");
            if target.callback.send(vec![]).is_err() {
                warn!("Failed to callback");
            }
        } else {
            let query_config = FindNodeQueryConfig::new_from_config(&self.config);
            self.queries
                .add_findnode_query(query_config, target, known_closest_peers);
        }
    }

    /// Internal function that starts a query.
    fn start_predicate_query(
        &mut self,
        target_node: NodeId,
        num_nodes: usize,
        predicate: Box<dyn Fn(&Enr) -> bool + Send>,
        callback: oneshot::Sender<Vec<Enr>>,
    ) {
        let mut target = QueryInfo {
            query_type: QueryType::FindNode(target_node),
            untrusted_enrs: Default::default(),
            distances_to_request: DISTANCES_TO_REQUEST_PER_PEER,
            callback,
        };

        let target_key: kbucket::Key<NodeId> = target.key();

        // Map the TableEntry to an ENR.
        let kbucket_predicate = |e: &Enr| predicate(e);

        let mut known_closest_peers = Vec::<kbucket::PredicateKey<_>>::new();
        {
            let mut kbuckets = self.kbuckets.write();
            for closest in kbuckets.closest_values_predicate(&target_key, &kbucket_predicate) {
                // Add the known ENRs to the untrusted list
                target.untrusted_enrs.push(closest.value.clone());
                // Add the key to the list for the query
                known_closest_peers.push(closest.into());
            }
        };

        if known_closest_peers.is_empty() {
            warn!("No known_closest_peers found. Return empty result without sending query.");
            if target.callback.send(vec![]).is_err() {
                warn!("Failed to callback");
            }
        } else {
            let mut query_config = PredicateQueryConfig::new_from_config(&self.config);
            query_config.num_results = num_nodes;
            self.queries
                .add_predicate_query(query_config, target, known_closest_peers, predicate);
        }
    }

    /// Returns an ENR if one is known for the given NodeId.
    pub fn find_enr(&self, node_id: &NodeId) -> Option<Enr> {
        // check if we know this node id in our routing table
        let key = kbucket::Key::from(*node_id);
        if let kbucket::Entry::Present(entry, _) = self.kbuckets.write().entry(&key) {
            return Some(entry.value().clone());
        }
        // check the untrusted addresses for ongoing queries
        for query in self.queries.iter() {
            if let Some(enr) = query
                .target()
                .untrusted_enrs
                .iter()
                .find(|v| v.node_id() == *node_id)
            {
                return Some(enr.clone());
            }
        }
        None
    }

    /// Processes an RPC request from a peer. Requests respond to the received socket address,
    /// rather than the IP of the known ENR.
    fn handle_rpc_request(&mut self, node_address: NodeAddress, req: Request) {
        let id = req.id;
        match req.body {
            RequestBody::FindNode { distances } => {
                self.send_nodes_response(node_address, id, distances);
            }
            RequestBody::Ping { enr_seq } => {
                // check if we need to update the known ENR
                let mut to_request_enr = None;
                match self.kbuckets.write().entry(&node_address.node_id.into()) {
                    kbucket::Entry::Present(ref mut entry, _) => {
                        if entry.value().seq() < enr_seq {
                            let enr = entry.value().clone();
                            to_request_enr = Some(enr);
                        }
                    }
                    kbucket::Entry::Pending(ref mut entry, _) => {
                        if entry.value().seq() < enr_seq {
                            let enr = entry.value().clone();
                            to_request_enr = Some(enr);
                        }
                    }
                    kbucket::Entry::Absent(_) => {
                        // We do not have a record of their ENR. So we do not care about the ENR
                        // update.
                        // If this ENR has updated its ENR to indicate it is now behind a NAT, we
                        // do not bother with re-evaluating whether it can fit into our routing
                        // table. It may get another chance once it's session expires.
                    }
                    kbucket::Entry::SelfEntry => {} // Shouldn't be possible, but don't update
                                                    // our own ENR.
                }
                if let Some(enr) = to_request_enr {
                    match NodeContact::try_from_enr(&enr, self.config.ip_mode) {
                        Ok(contact) => {
                            self.request_enr(contact, None);
                        }
                        Err(NonContactable { enr }) => {
                            debug_unreachable!("Stored ENR is not contactable. {}", enr);
                            error!(
                                "Stored ENR is not contactable! This should never happen {}",
                                enr
                            );
                        }
                    }
                }

                // build the PONG response
                let src = node_address.socket_addr;
                let response = Response {
                    id,
                    body: ResponseBody::Pong {
                        enr_seq: self.local_enr.read().seq(),
                        ip: src.ip(),
                        port: src.port(),
                    },
                };
                debug!("Sending PONG response to {}", node_address);
                if let Err(e) = self
                    .handler_send
                    .send(HandlerIn::Response(node_address, Box::new(response)))
                {
                    warn!("Failed to send response {}", e)
                }
            }
            RequestBody::Talk { protocol, request } => {
                let req = TalkRequest {
                    id,
                    node_address,
                    protocol,
                    body: request,
                    sender: Some(self.handler_send.clone()),
                };

                self.send_event(Discv5Event::TalkRequest(req));
            }
            RequestBody::RegisterTopic { .. } => {
                debug!("Received RegisterTopic request which is unimplemented");
            }
            RequestBody::TopicQuery { .. } => {
                debug!("Received TopicQuery request which is unimplemented");
            }
            RequestBody::RelayRequest {
                from_enr,
                to_node_id,
            } => {
                let local_node_id = self.local_enr.read().node_id();
                if to_node_id == local_node_id {
                    // This node is the receiver

                    if from_enr.node_id() == node_address.node_id {
                        debug!("Node acting as a rendezvous node for itself as initiator. Blacklisting peer: {}", node_address);
                        let ban_timeout = self.config.ban_duration.map(|v| Instant::now() + v);
                        PERMIT_BAN_LIST.write().ban(node_address, ban_timeout);
                        return;
                    }

                    // If this node is advertising that it is not behind a NAT, we do a peer
                    // vote to verify this.
                    if self.config.enr_update
                        && (self.local_enr.read().udp4_socket().is_some()
                            || self.local_enr.read().udp6_socket().is_some())
                        && self.peer_votes.is_behind_nat(
                            self.kbuckets
                                .write()
                                .iter()
                                .map(|node| node.status.direction),
                        )
                    {
                        debug!("This node appears to be behind a NAT. Updating local ENR.");
                        let mut updated = false;
                        if let Some(socket) =
                            self.local_enr.read().udp4_socket().map(SocketAddr::V4)
                        {
                            match self.local_enr.write().set_udp_socket_nat(
                                &self.enr_key.read(),
                                socket.ip(),
                                Some(socket.port()),
                            ) {
                                Ok(_) => {
                                    debug!(
                                        "Updated local ENR's 'nat' and 'udp' field with socket {}",
                                        socket
                                    );
                                    updated = true;
                                }
                                Err(e) => {
                                    warn!("Failed to update local NAT socket. socket: {}, error: {:?}", socket, e);
                                }
                            }
                        }
                        if let Some(socket6) =
                            self.local_enr.read().udp6_socket().map(SocketAddr::V6)
                        {
                            match self.local_enr.write().set_udp_socket_nat(
                                &self.enr_key.read(),
                                socket6.ip(),
                                Some(socket6.port()),
                            ) {
                                Ok(_) => {
                                    debug!(
                                                "Updated local ENR's 'nat6' and 'udp6' field with socket {}",
                                                socket6
                                            );
                                    updated = true;
                                }
                                Err(e) => {
                                    warn!("Failed to update local NAT socket. socket: {}, error: {:?}", socket6, e);
                                }
                            }
                        }

                        if updated {
                            trace!("Pinging connected peers to inform them that our ENR is updated to show this node is behind a NAT");
                            self.ping_connected_peers();
                            self.update_peers_to_ping_nat();
                        }
                    }

                    if self.local_enr.read().supports_nat() {
                        // Accept relay request
                        // Only try to establish sessions with a peer behind a NAT with one
                        // relay at a time.
                        if self.hole_punch_pings.get(&from_enr.node_id()).is_none() {
                            trace!("Receiver node sending PING to initiator node");
                            self.send_ping(&from_enr, true);
                            trace!("Receiver node sending RELAYRESPONSE to rendezvous node");
                            self.send_relay_response(node_address, id, RelayResponseCode::True);
                        } else {
                            trace!("Receiver node sending RELAYRESPONSE to rendezvous node");
                            self.send_relay_response(node_address, id, RelayResponseCode::False);
                        }
                    }
                } else if from_enr.node_id() != local_node_id {
                    // This node is the rendezvous

                    if !self.local_enr.read().supports_nat() {
                        return;
                    }

                    if to_node_id == node_address.node_id {
                        debug!("Node acting as a rendezvous node for itself as receiver. Blacklisting peer: {}", node_address);
                        let ban_timeout = self.config.ban_duration.map(|v| Instant::now() + v);
                        PERMIT_BAN_LIST.write().ban(node_address, ban_timeout);
                        return;
                    }

                    // Requests are only relayed to peers in the local routing table, i.e. that we
                    // have possibly passed in a NODES response to the initiator and are connected
                    // and support the NAT traversal protocol.
                    let key = kbucket::Key::from(to_node_id);
                    let receiver = match self.kbuckets.write().entry(&key) {
                        kbucket::Entry::Present(entry, status)
                            if status.is_connected() && entry.value().supports_nat() =>
                        {
                            Some(entry.value().clone())
                        }
                        _ => None,
                    };
                    if let Some(receiver) = receiver
                    // check if we know this node id in our routing table
                    {
                        if let Some(contact) = self.contact_from_enr(&receiver) {
                            trace!("Rendezvous node sending RELAYREQUEST to receiver node");
                            if let Ok(req_id) =
                                self.send_relay_request(contact, from_enr, to_node_id)
                            {
                                self.relayed_requests.insert(
                                    req_id,
                                    RelayedRequest {
                                        initiator: node_address,
                                        req_id_from_initiator: id,
                                    },
                                );
                            }
                        }
                    } else {
                        // This node is currently not connected to the receiver and is hence not a
                        // suitable relay.
                        self.send_relay_response(node_address, id, RelayResponseCode::Error);
                    }
                }
            }
        }
    }

    /// Processes an RPC response from a peer.
    fn handle_rpc_response(&mut self, node_address: NodeAddress, response: Response) {
        // verify we know of the rpc_id
        let id = response.id.clone();

        if let Some(mut active_request) = self.active_requests.remove(&id) {
            let node_contact = active_request.contact.clone();
            debug!(
                "Received RPC response: {} to request: {} from: {}",
                response.body, active_request.request_body, node_contact
            );

            // Check that the responder matches the expected request

            let expected_node_address = node_contact.node_address();
            if expected_node_address != node_address {
                debug_unreachable!("Handler returned a response not matching the used socket addr");
                return error!("Received a response from an unexpected address. Expected {}, received {}, request_id {}", expected_node_address, node_address, id);
            }

            if !response.match_request(&active_request.request_body) {
                warn!(
                    "Node gave an incorrect response type. Ignoring response from: {}",
                    node_address
                );
                return;
            }

            let node_id = node_address.node_id;

            match response.body {
                ResponseBody::Nodes { total, mut nodes } => {
                    if total > MAX_NODES_RESPONSES as u64 {
                        warn!(
                            "NodesResponse has a total larger than {}, nodes will be truncated",
                            MAX_NODES_RESPONSES
                        );
                    }

                    // These are sanitized and ordered
                    let distances_requested = match &active_request.request_body {
                        RequestBody::FindNode { distances } => distances,
                        _ => unreachable!(),
                    };

                    // This could be an ENR request from the outer service. If so respond to the
                    // callback and End.
                    if let Some(CallbackResponse::Enr(callback)) = active_request.callback.take() {
                        // Currently only support requesting for ENRs. Verify this is the case.
                        if !distances_requested.is_empty() && distances_requested[0] != 0 {
                            error!("Retrieved a callback request that wasn't for a peer's ENR");
                            return;
                        }
                        // This must be for asking for an ENR
                        if nodes.len() > 1 {
                            warn!(
                                "Peer returned more than one ENR for itself. {}",
                                node_contact
                            );
                        }
                        let response = nodes
                            .pop()
                            .ok_or(RequestError::InvalidEnr("Peer did not return an ENR"));
                        if let Err(e) = callback.send(response) {
                            warn!("Failed to send response in callback {:?}", e)
                        }
                        return;
                    }

                    // Filter out any nodes that are not of the correct distance
                    let peer_key: kbucket::Key<NodeId> = node_id.into();

                    // The distances we send are sanitized and ordered.
                    // We never send an ENR request in combination of other requests.
                    if distances_requested.len() == 1 && distances_requested[0] == 0 {
                        // we requested an ENR update
                        if nodes.len() > 1 {
                            warn!(
                                "Peer returned more than one ENR for itself. Blacklisting {}",
                                node_address
                            );
                            let ban_timeout = self.config.ban_duration.map(|v| Instant::now() + v);
                            PERMIT_BAN_LIST.write().ban(node_address, ban_timeout);
                            nodes.retain(|enr| {
                                peer_key.log2_distance(&enr.node_id().into()).is_none()
                            });
                        }
                    } else {
                        let before_len = nodes.len();
                        nodes.retain(|enr| {
                            peer_key
                                .log2_distance(&enr.node_id().into())
                                .map(|distance| distances_requested.contains(&distance))
                                .unwrap_or_else(|| false)
                        });

                        if nodes.len() < before_len {
                            // Peer sent invalid ENRs. Blacklist the Node
                            warn!("Peer sent invalid ENR. Blacklisting {}", node_contact);
                            let ban_timeout = self.config.ban_duration.map(|v| Instant::now() + v);
                            PERMIT_BAN_LIST.write().ban(node_address, ban_timeout);
                        }
                    }

                    // handle the case that there is more than one response
                    if total > 1 {
                        let mut current_response = self
                            .active_nodes_responses
                            .remove(&node_id)
                            .unwrap_or_default();

                        debug!(
                            "Nodes Response: {} of {} received",
                            current_response.count, total
                        );
                        // If there are more requests coming, store the nodes and wait for
                        // another response
                        // If we have already received all our required nodes, drop any extra
                        // rpc messages.
                        if current_response.received_nodes.len() < self.config.max_nodes_response
                            && (current_response.count as u64) < total
                            && current_response.count < MAX_NODES_RESPONSES
                        {
                            current_response.count += 1;

                            current_response.received_nodes.append(&mut nodes);
                            self.active_nodes_responses
                                .insert(node_id, current_response);
                            self.active_requests.insert(id, active_request);
                            return;
                        }

                        // have received all the Nodes responses we are willing to accept
                        // ignore duplicates here as they will be handled when adding
                        // to the DHT
                        current_response.received_nodes.append(&mut nodes);
                        nodes = current_response.received_nodes;
                    }

                    debug!(
                        "Received a nodes response of len: {}, total: {}, from: {}",
                        nodes.len(),
                        total,
                        node_contact
                    );
                    // note: If a peer sends an initial NODES response with a total > 1 then
                    // in a later response sends a response with a total of 1, all previous nodes
                    // will be ignored.
                    // ensure any mapping is removed in this rare case
                    self.active_nodes_responses.remove(&node_id);

                    self.discovered(&node_contact, nodes, active_request.query_id);
                }
                ResponseBody::Pong { enr_seq, ip, port } => {
                    let socket = SocketAddr::new(ip, port);
                    // perform ENR majority-based update if required.

                    // Only count votes that are from peers we have contacted.
                    let key: kbucket::Key<NodeId> = node_id.into();
                    let should_count = matches!(
                        self.kbuckets.write().entry(&key),
                        kbucket::Entry::Present(_, status)
                            if status.is_connected() && !status.is_incoming());

                    if should_count {
                        trace!("Counting ip vote from peer {}", node_id);
                        self.peer_votes.register_ip_vote(node_id, socket);
                        let (majority4, majority6) = self.peer_votes.current_majority_ip();

                        let mut updated = false;

                        match majority4 {
                            Some(Address::SymmetricNAT(ip)) => {
                                trace!("A WAN reachable address {} found for this node which appears to be behind a symmetric NAT as no general port could be found", ip);
                                // Check if our advertised external IP address needs to be
                                // updated.
                                if Some(socket.ip()) != self.local_enr.read().nat4().map(IpAddr::V4)
                                {
                                    match self.local_enr.write().set_udp_socket_nat(
                                        &self.enr_key.read(),
                                        socket.ip(),
                                        None,
                                    ) {
                                        Ok(_) => {
                                            updated = true;
                                            info!("Local NAT ip address updated to {}", ip);
                                        }
                                        Err(e) => {
                                            warn!("Failed to update local NAT ip address. ip: {}, error: {:?}", ip, e);
                                        }
                                    }
                                }
                            }
                            Some(Address::Reachable(socket)) => {
                                trace!("A WAN reachable address {} found for this node", socket);
                                // Check if our advertised external IP address needs to be
                                // updated.
                                if Some(socket)
                                    != self.local_enr.read().udp4_socket().map(SocketAddr::V4)
                                {
                                    let result = self
                                        .local_enr
                                        .write()
                                        .set_udp_socket(socket, &self.enr_key.read());
                                    match result {
                                        Ok(_) => {
                                            updated = true;
                                            info!("Local UDP socket updated to: {}", socket);
                                            self.send_event(Discv5Event::SocketUpdated(socket));
                                        }
                                        Err(e) => {
                                            warn!("Failed to update local UDP socket. ip: {}, error: {:?}", socket, e);
                                        }
                                    }
                                }
                            }
                            None => {}
                        }

                        match majority6 {
                            Some(Address::SymmetricNAT(ip)) => {
                                trace!("A WAN reachable address ipv6 {} found for this node which appears to be behind a symmetric NAT as no general port could be found", ip);
                                // Check if our advertised external IP address needs to be
                                // updated.
                                if Some(socket.ip()) != self.local_enr.read().nat6().map(IpAddr::V6)
                                {
                                    // WARNING: In the case of a symmetric NAT the port field
                                    // will be None or non-existent. The node receiving the
                                    // connection is responsible for storing the port used for
                                    // the connection from the peer behind a symmetric NAT.
                                    match self.local_enr.write().set_udp_socket_nat(
                                        &self.enr_key.read(),
                                        socket.ip(),
                                        None,
                                    ) {
                                        Ok(_) => {
                                            updated = true;
                                            info!("Local NAT ipv6 address updated to: {}", ip);
                                        }
                                        Err(e) => {
                                            warn!("Failed to update local NAT ipv6 address. ipv6: {}, error: {:?}", ip, e);
                                        }
                                    }
                                }
                            }
                            Some(Address::Reachable(socket)) => {
                                trace!(
                                    "A WAN reachable ipv6 address {} found for this node",
                                    socket
                                );
                                // Check if our advertised external IP address needs to be
                                // updated.
                                if Some(socket)
                                    != self.local_enr.read().udp6_socket().map(SocketAddr::V6)
                                {
                                    let result = self
                                        .local_enr
                                        .write()
                                        .set_udp_socket(socket, &self.enr_key.read());
                                    match result {
                                        Ok(_) => {
                                            updated = true;
                                            info!("Local UDP socket updated to: {}", socket);
                                            self.send_event(Discv5Event::SocketUpdated(socket));
                                        }
                                        Err(e) => {
                                            warn!("Failed to update local UDP socket. ip: {}, error: {:?}", socket, e);
                                        }
                                    }
                                }
                            }
                            None => {}
                        }
                        if updated {
                            self.ping_connected_peers();
                            self.update_peers_to_ping_nat();
                        }
                    }

                    // check if we need to request a new ENR
                    if let Some(enr) = self.find_enr(&node_id) {
                        if enr.seq() < enr_seq {
                            // request an ENR update
                            debug!("Requesting an ENR update from: {}", node_contact);
                            let request_body = RequestBody::FindNode { distances: vec![0] };
                            let active_request = ActiveRequest {
                                contact: node_contact,
                                request_body,
                                query_id: None,
                                callback: None,
                                relay: None,
                            };
                            _ = self.send_rpc_request(active_request);
                        }
                        self.connection_updated(node_id, ConnectionStatus::PongReceived(enr));
                    }
                }
                ResponseBody::Talk { response } => {
                    // Send the response to the user
                    match active_request.callback {
                        Some(CallbackResponse::Talk(callback)) => {
                            if let Err(e) = callback.send(Ok(response)) {
                                warn!("Failed to send callback response {:?}", e)
                            };
                        }
                        _ => error!("Invalid callback for response"),
                    }
                }
                ResponseBody::Ticket { .. } => {
                    error!("Received a TICKET response. This is unimplemented and should be unreachable.");
                }
                ResponseBody::RelayResponse { response } => {
                    if let RequestBody::RelayRequest {
                        ref from_enr,
                        to_node_id,
                    } = active_request.request_body
                    {
                        let local_node_id = self.local_enr.read().node_id();
                        if from_enr.node_id() == local_node_id {
                            // This node is the initiator
                            let receiver_enr = self.receiver_enrs.remove(&to_node_id);

                            match response {
                                RelayResponseCode::False => {
                                    debug!("Receiver doesn't want to connect via this rendezvous, possibly it's already doing NAT traversal with another rendezvous");
                                }
                                RelayResponseCode::True => {
                                    trace!("Sending hole punch ping...");
                                    if let Some(to_enr) = receiver_enr {
                                        trace!("Found enr {}", to_enr);
                                        self.send_ping(&to_enr, true);
                                    } else {
                                        trace!("Couldn't find ENR of receiver");
                                    }
                                }
                                RelayResponseCode::Error => {
                                    debug!("Rendezvous didn't get a response from the receiver");
                                }
                            }
                        } else if to_node_id != local_node_id {
                            // This node is the rendezvous
                            if let Some(initiator_req) = self.relayed_requests.remove(&id) {
                                self.send_relay_response(
                                    initiator_req.initiator,
                                    initiator_req.req_id_from_initiator,
                                    response,
                                );
                            }
                        }
                    }
                }
            }
        } else {
            warn!(
                "Received an RPC response which doesn't match a request. Id: {}",
                id
            );
        }
    }

    // Send RPC Requests //

    /// Sends a PING request to a node.
    fn send_ping(&mut self, enr: &Enr, is_hole_punch: bool) {
        if let Some(contact) = self.contact_from_enr(enr) {
            let request_body = RequestBody::Ping {
                enr_seq: self.local_enr.read().seq(),
            };
            let active_request = ActiveRequest {
                contact,
                request_body,
                query_id: None,
                callback: None,
                relay: None,
            };
            if is_hole_punch {
                self.hole_punch_pings.insert(enr.node_id());
                self.send_hole_punch_ping(active_request);
            } else {
                _ = self.send_rpc_request(active_request);
            }
        }
    }

    /// Sends a PING request to a node.
    fn send_hole_punch_ping(&mut self, active_request: ActiveRequest) {
        // Generate a random rpc_id which is matched per node id
        let id = RequestId::random();
        let request: Request = Request {
            id: id.clone(),
            body: active_request.request_body.clone(),
        };
        let contact = active_request.contact;

        debug!("Sending RPC {} to node: {}", request, contact);
        if let Err(e) = self
            .handler_send
            .send(HandlerIn::HolePunch(contact, Box::new(request)))
        {
            error!(
                "Failed to send request {} to the handler layer. Error: {}",
                id, e
            );
        }
    }

    /// Ping all peers that are connected in the routing table.
    fn ping_connected_peers(&mut self) {
        let connected_peers = {
            let mut kbuckets = self.kbuckets.write();
            kbuckets
                .iter()
                .filter_map(|entry| {
                    if entry.status.is_connected() {
                        Some(entry.node.value.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };

        for enr in connected_peers {
            self.send_ping(&enr, false);
        }
    }

    /// Request an external node's ENR.
    fn request_enr(
        &mut self,
        contact: NodeContact,
        callback: Option<oneshot::Sender<Result<Enr, RequestError>>>,
    ) {
        let request_body = RequestBody::FindNode { distances: vec![0] };
        let active_request = ActiveRequest {
            contact,
            request_body,
            query_id: None,
            callback: callback.map(CallbackResponse::Enr),
            relay: None,
        };
        _ = self.send_rpc_request(active_request);
    }

    /// Requests a TALK message from the peer.
    fn talk_request(
        &mut self,
        contact: NodeContact,
        protocol: Vec<u8>,
        request: Vec<u8>,
        callback: oneshot::Sender<Result<Vec<u8>, RequestError>>,
    ) {
        let request_body = RequestBody::Talk { protocol, request };

        let active_request = ActiveRequest {
            contact,
            request_body,
            query_id: None,
            callback: Some(CallbackResponse::Talk(callback)),
            relay: None,
        };
        _ = self.send_rpc_request(active_request);
    }

    /// An initiator node sends a RELAYREQUEST request to a rendezvous node requesting it to help
    /// establish a connection to a receiver node behind a nat. The rendezvous node relays the
    /// RELAYREQUEST request on to the receiver.
    fn send_relay_request(
        &mut self,
        contact: NodeContact,
        from_enr: Enr,
        to_node_id: NodeId,
    ) -> Result<RequestId, &str> {
        let active_request = ActiveRequest {
            contact,
            request_body: RequestBody::RelayRequest {
                from_enr,
                to_node_id,
            },
            query_id: None,
            callback: None,
            relay: None,
        };
        self.send_rpc_request(active_request)
    }

    /// A receiver node sends a RELAYRESPONSE in response to a RELAYREQUEST to a rendezvous node,
    /// the rendezvous node relays the RELAYRESPONSE response to the initiator.
    fn send_relay_response(
        &mut self,
        node_address: NodeAddress,
        id: RequestId,
        response: RelayResponseCode,
    ) {
        let response = Response {
            id,
            body: ResponseBody::RelayResponse { response },
        };
        trace!(
            "Sending RELAYRESPONSE response to: {}. Response: {} ",
            node_address,
            response
        );
        if let Err(e) = self
            .handler_send
            .send(HandlerIn::Response(node_address, Box::new(response)))
        {
            warn!("Failed to send RELAYRESPONSE response {}", e)
        }
    }

    /// Sends a NODES response, given a list of found ENRs. This function splits the nodes up
    /// into multiple responses to ensure the response stays below the maximum packet size.
    fn send_nodes_response(
        &mut self,
        node_address: NodeAddress,
        rpc_id: RequestId,
        mut distances: Vec<u64>,
    ) {
        let mut nodes_to_send = Vec::new();
        distances.sort_unstable();
        distances.dedup();

        if let Some(0) = distances.first() {
            // if the distance is 0 send our local ENR
            nodes_to_send.push(self.local_enr.read().clone());
            debug!("Sending our ENR to node: {}", node_address);
            trace!(
                "Local ENR ip4 {:?} and ip6 {:?}",
                self.local_enr.read().ip4(),
                self.local_enr.read().ip6()
            );
            trace!(
                "Local ENR udp4 port {:?} and udp6 port {:?}",
                self.local_enr.read().udp4(),
                self.local_enr.read().udp6(),
            );
            distances.remove(0);
        }

        if !distances.is_empty() {
            let mut kbuckets = self.kbuckets.write();
            for node in kbuckets
                .nodes_by_distances(distances.as_slice(), self.config.max_nodes_response)
                .into_iter()
                .filter_map(|entry| {
                    let peer = entry.node;
                    let enr = peer.value;
                    trace!(
                        "Local ENR nat ip4 {:?} and nat ip6 {:?}",
                        self.local_enr.read().ip4(),
                        self.local_enr.read().ip6(),
                    );
                    if enr.udp4_socket().is_none() && enr.udp6_socket().is_none() {
                        if enr.udp4_socket_nat().is_some() || enr.udp6_socket_nat().is_some() {
                            // A node may be aware it is behind a NAT but still not supporting the
                            // NAT traversal protocol. It makes no sense to recommend these nodes
                            // to peers.

                            // Only send peers behind asymmetric NATs which we have a good
                            // chance of immediately being able to play relays for because we are
                            // connected to them.
                            if !enr.supports_nat() || !entry.status.is_connected() {
                                return None;
                            }
                        } else {
                            // Only send nodes that are not behind a NAT, that are port-forwarded
                            // or are behind an asymmetric NAT, i.e. with a reachable port in its
                            // ENR. No port in the 'udp'/'udp6' field and an ip in the 'nat'/'nat6'
                            // field is associated with a node behind a symmetric NAT.
                            return None;
                        }
                    }
                    if peer.key.preimage() != &node_address.node_id {
                        return Some(enr.clone());
                    }
                    None
                })
            {
                nodes_to_send.push(node);
            }
        }

        // if there are no nodes, send an empty response
        if nodes_to_send.is_empty() {
            let response = Response {
                id: rpc_id,
                body: ResponseBody::Nodes {
                    total: 1u64,
                    nodes: Vec::new(),
                },
            };
            trace!(
                "Sending empty FINDNODES response to: {}",
                node_address.node_id
            );
            if let Err(e) = self
                .handler_send
                .send(HandlerIn::Response(node_address, Box::new(response)))
            {
                warn!("Failed to send empty FINDNODES response {}", e)
            }
        } else {
            // build the NODES response
            let mut to_send_nodes: Vec<Vec<Enr>> = Vec::new();
            let mut total_size = 0;
            let mut rpc_index = 0;
            to_send_nodes.push(Vec::new());
            for enr in nodes_to_send.into_iter() {
                let entry_size = rlp::encode(&enr).len();
                // Responses assume that a session is established. Thus, on top of the encoded
                // ENRs the packet should be a regular message. A regular message has an IV (16
                // bytes), and a header of 55 bytes. The find-nodes RPC requires 16 bytes for the
                // ID and the `total` field. Also there is a 16 byte HMAC for encryption and an
                // extra byte for RLP encoding.
                //
                // Furthermore, we could be responding via an auth-header which can take up to 282
                // bytes in its header. In that case we would have even less space for the ENRs.
                //
                // As most messages will be normal messages we will try and pack as many ENRs we
                // can in and drop the response packet if a user requests an auth message of a very
                // packed response.
                //
                // The estimated total overhead for a regular message is therefore 104 bytes.
                if entry_size + total_size < MAX_PACKET_SIZE - 104 {
                    total_size += entry_size;
                    trace!(
                        "Adding ENR {}, size {}, total size {}",
                        enr,
                        entry_size,
                        total_size
                    );
                    to_send_nodes[rpc_index].push(enr);
                } else {
                    total_size = entry_size;
                    to_send_nodes.push(vec![enr]);
                    rpc_index += 1;
                }
            }

            let responses: Vec<Response> = to_send_nodes
                .into_iter()
                .map(|nodes| Response {
                    id: rpc_id.clone(),
                    body: ResponseBody::Nodes {
                        total: (rpc_index + 1) as u64,
                        nodes,
                    },
                })
                .collect();

            for response in responses {
                trace!(
                    "Sending FINDNODES response to: {}. Response: {} ",
                    node_address,
                    response
                );
                if let Err(e) = self.handler_send.send(HandlerIn::Response(
                    node_address.clone(),
                    Box::new(response),
                )) {
                    warn!("Failed to send FINDNODES response {}", e)
                }
            }
        }
    }

    /// Constructs and sends a request RPC to the session service given a `QueryInfo`.
    fn send_rpc_query(
        &mut self,
        query_id: QueryId,
        return_peer: NodeId,
        request_body: RequestBody,
    ) {
        // find the ENR associated with the query
        if let Some(enr) = self.find_enr(&return_peer) {
            if let Some(contact) = self.contact_from_enr(&enr) {
                let relay = self.query_peer_relays.remove(&return_peer);
                let active_request = ActiveRequest {
                    contact,
                    request_body,
                    query_id: Some(query_id),
                    callback: None,
                    relay,
                };
                _ = self.send_rpc_request(active_request);
                // Request successfully sent
                return;
            }
        } else {
            error!("Query {} requested an unknown ENR", *query_id);
        }

        // This query request has failed and we must inform the
        // query of the failed request.
        // TODO: Come up with a better design to ensure that all query RPC requests
        // are forced to be responded to.
        if let Some(query) = self.queries.get_mut(query_id) {
            query.on_failure(&return_peer);
        }
    }

    /// Sends generic RPC requests. Each request gets added to known outputs, awaiting a response.
    fn send_rpc_request(&mut self, active_request: ActiveRequest) -> Result<RequestId, &str> {
        // Generate a random rpc_id which is matched per node id
        let id = RequestId::random();
        let request: Request = Request {
            id: id.clone(),
            body: active_request.request_body.clone(),
        };
        let contact = active_request.contact.clone();

        debug!("Sending RPC {} to node: {}", request, contact);
        match self
            .handler_send
            .send(HandlerIn::Request(contact, Box::new(request)))
        {
            Ok(_) => {
                self.active_requests.insert(id.clone(), active_request);
                Ok(id)
            }
            Err(e) => {
                error!(
                    "Failed to send request {} to the handler layer. Error: {}",
                    id, e
                );
                Err("Failed to send request")
            }
        }
    }

    fn send_event(&mut self, event: Discv5Event) {
        if let Some(stream) = self.event_stream.as_mut() {
            if let Err(mpsc::error::TrySendError::Closed(_)) = stream.try_send(event) {
                // If the stream has been dropped prevent future attempts to send events
                self.event_stream = None;
            }
        }
    }

    /// Processes discovered peers from a query.
    fn discovered(&mut self, source: &NodeContact, mut enrs: Vec<Enr>, query_id: Option<QueryId>) {
        let local_id = self.local_enr.read().node_id();
        enrs.retain(|enr| {
            if enr.node_id() == local_id {
                return false;
            }

            // If any of the discovered nodes are in the routing table, and there contains an
            // older ENR, update it.
            // If there is an event stream send the Discovered event
            if self.config.report_discovered_peers {
                self.send_event(Discv5Event::Discovered(enr.clone()));
            }

            // ignore peers that don't pass the table filter
            if (self.config.table_filter)(enr) {
                let key = kbucket::Key::from(enr.node_id());

                // If the ENR exists in the routing table and the discovered ENR has a greater
                // sequence number, perform some filter checks before updating the enr.

                let must_update_enr = match self.kbuckets.write().entry(&key) {
                    kbucket::Entry::Present(entry, _) => entry.value().seq() < enr.seq(),
                    kbucket::Entry::Pending(mut entry, _) => entry.value().seq() < enr.seq(),
                    _ => false,
                };

                if must_update_enr {
                    if let UpdateResult::Failed(reason) =
                        self.kbuckets.write().update_node(&key, enr.clone(), None)
                    {
                        self.peers_to_ping.remove(&enr.node_id());
                        debug!(
                            "Failed to update discovered ENR. Node: {}, Reason: {:?}",
                            source, reason
                        );
                        // Remove this peer from the discovered list if the update failed
                        return false;
                    }
                }
            } else {
                return false; // Didn't pass the table filter remove the peer
            }

            // The remaining ENRs are used if this request was part of a query. If we are
            // requesting the target of the query, this ENR could be the result of requesting the
            // target-nodes own id. We don't want to add this as a "new" discovered peer in the
            // query, so we remove it from the discovered list here.
            source.node_id() != enr.node_id()
        });

        enrs.retain(|enr| {
            if self.local_enr.read().supports_nat() {
                // If a discovered node flags that it is behind an asymmetric NAT, send it a relay
                // request directly instead of adding it to a query (avoid waiting for a request to
                // the new peer to timeout).
                if self.config.ip_mode.get_contactable_addr_nat(enr).is_some() {
                    let key = kbucket::Key::from(enr.node_id());
                    let mut new_nat_peer = false;
                    match self.kbuckets.write().entry(&key) {
                        kbucket::Entry::Absent(_) => {
                            new_nat_peer = true;
                        }
                        kbucket::Entry::Present(..) | kbucket::Entry::Pending(..) => {
                            // Keep enr and pass on to query if it is behind an asymmetric NAT but
                            // has been previously contacted.
                            return true;
                        }
                        _ => {}
                    }
                    if new_nat_peer {
                        // Try to hole-punch peer's NAT instead of pass to query.
                        let local_enr = self.local_enr.read().clone();
                        let to_node_id = enr.node_id();
                        // Finish one relay request to a given peer before starting another
                        if let Entry::Vacant(e) = self.receiver_enrs.entry(to_node_id) {
                            e.insert(enr.clone());
                            _ = self.send_relay_request(source.clone(), local_enr, to_node_id);
                        }
                        return false;
                    }
                }
            }
            if self.config.ip_mode.get_contactable_addr(enr).is_some() {
                // Keep enr and pass on to query if it flags it is not behind a NAT or
                // port-forwarded.
                return true;
            }
            // Filter out peers that are behind a symmetric NAT or have uncontactable ENRs
            // (shouldn't be passed in NODES responses).
            false
        });

        // If this is part of a query, update the query
        if let Some(query_id) = query_id {
            if let Some(query) = self.queries.get_mut(query_id) {
                let mut peer_count = 0;
                for enr_ref in enrs.iter() {
                    if !query
                        .target_mut()
                        .untrusted_enrs
                        .iter()
                        .any(|e| e.node_id() == enr_ref.node_id())
                    {
                        query.target_mut().untrusted_enrs.push(enr_ref.clone());
                        self.query_peer_relays
                            .insert(enr_ref.node_id(), source.node_id());
                    }
                    peer_count += 1;
                }
                debug!("{} peers found for query id {:?}", peer_count, query_id);
                query.on_success(&source.node_id(), &enrs)
            } else {
                debug!("Response returned for ended query {:?}", query_id)
            }
        }
    }

    /// Update the connection status of a node in the routing table.
    /// This tracks whether or not we should be pinging peers. Disconnected peers are removed from
    /// the queue and newly added peers to the routing table are added to the queue.
    fn connection_updated(&mut self, node_id: NodeId, new_status: ConnectionStatus) {
        // Variables to that may require post-processing
        let mut ping_peer = None;
        let mut event_to_send = None;

        let key = kbucket::Key::from(node_id);
        match new_status {
            ConnectionStatus::Connected(enr, direction) => {
                // attempt to update or insert the new ENR.
                let status = NodeStatus {
                    state: ConnectionState::Connected,
                    direction,
                };
                match self.kbuckets.write().insert_or_update(&key, enr, status) {
                    InsertResult::Inserted => {
                        // We added this peer to the table
                        debug!("New connected node added to routing table: {}", node_id);
                        self.peers_to_ping.insert(node_id);
                        let event = Discv5Event::NodeInserted {
                            node_id,
                            replaced: None,
                        };
                        event_to_send = Some(event);
                    }
                    InsertResult::Pending { disconnected } => {
                        ping_peer = Some(disconnected);
                    }
                    InsertResult::StatusUpdated {
                        promoted_to_connected,
                    }
                    | InsertResult::Updated {
                        promoted_to_connected,
                    } => {
                        // The node was updated
                        if promoted_to_connected {
                            debug!("Node promoted to connected: {}", node_id);
                            self.peers_to_ping.insert(node_id);
                        }
                    }
                    InsertResult::ValueUpdated | InsertResult::UpdatedPending => {}
                    InsertResult::Failed(reason) => {
                        self.peers_to_ping.remove(&node_id);
                        trace!("Could not insert node: {}, reason: {:?}", node_id, reason);
                    }
                }
            }
            ConnectionStatus::PongReceived(enr) => {
                match self
                    .kbuckets
                    .write()
                    .update_node(&key, enr, Some(ConnectionState::Connected))
                {
                    UpdateResult::Failed(reason) => {
                        self.peers_to_ping.remove(&node_id);
                        debug!(
                            "Could not update ENR from pong. Node: {}, reason: {:?}",
                            node_id, reason
                        );
                    }
                    update => {
                        debug!("Updated {:?}", update)
                    } // Updated ENR successfully.
                }
            }
            ConnectionStatus::Disconnected => {
                // If the node has disconnected, remove any ping timer for the node.
                match self.kbuckets.write().update_node_status(
                    &key,
                    ConnectionState::Disconnected,
                    None,
                ) {
                    UpdateResult::Failed(reason) => match reason {
                        FailureReason::KeyNonExistent => {}
                        others => {
                            warn!(
                                "Could not update node to disconnected. Node: {}, Reason: {:?}",
                                node_id, others
                            );
                        }
                    },
                    _ => {
                        debug!("Node set to disconnected: {}", node_id)
                    }
                }
                self.peers_to_ping.remove(&node_id);
            }
        };

        // Post processing

        if let Some(event) = event_to_send {
            self.send_event(event);
        }

        if let Some(node_key) = ping_peer {
            let optional_enr = {
                if let kbucket::Entry::Present(entry, _status) =
                    self.kbuckets.write().entry(&node_key)
                {
                    // NOTE: We don't check the status of this peer. We try and ping outdated
                    // peers.
                    Some(entry.value().clone())
                } else {
                    None
                }
            };
            if let Some(enr) = optional_enr {
                self.send_ping(&enr, false)
            }
        }
    }

    /// The equivalent of libp2p `inject_connected()` for a udp session. We have no stream, but a
    /// session key-pair has been negotiated.
    fn inject_session_established(&mut self, enr: Enr, direction: ConnectionDirection) {
        // Ignore sessions with non-contactable ENRs
        if self.config.ip_mode.get_contactable_addr(&enr).is_none() {
            return;
        }

        let node_id = enr.node_id();
        debug!(
            "Session established with Node: {}, direction: {}",
            node_id, direction
        );

        // Register the incoming connection if required.
        if let ConnectionDirection::Incoming = direction {
            self.peer_votes.register_incoming_connection();
        }

        self.connection_updated(node_id, ConnectionStatus::Connected(enr, direction));
    }

    fn inject_session_established_nat(
        &mut self,
        enr: Enr,
        connection_direction: ConnectionDirection,
    ) {
        // Ignore sessions with non-contactable ENRs
        if self.config.ip_mode.get_contactable_addr_nat(&enr).is_none() {
            return;
        }

        let node_id = enr.node_id();
        debug!("Session established with node behind NAT: {}", node_id);
        self.connection_updated(
            node_id,
            ConnectionStatus::Connected(enr, connection_direction),
        );
    }

    fn inject_session_established_nat_symmetric(&mut self, enr: Enr, port: u16) {
        // Attempt adding the enr to the local routing table if this Discv5 instances stores
        // remote ports for connections from nodes behind a symmetric NAT.
        if let Some(ref mut symmetric_nat_peers_ports) = self.symmetric_nat_peers_ports {
            // Ignore sessions with non-contactable ENRs
            if self
                .config
                .ip_mode
                .get_contactable_addr_nat_symmetric(&enr, port)
                .is_none()
            {
                return;
            }

            // In case this is a node behind a symmetric NAT we need to store the port which
            // is unique for this connection and hence will not eventually be advertised in
            // the peer's ENR.
            let node_id = enr.node_id();
            let peer_key: kbucket::Key<NodeId> = node_id.into();
            if let Some(distance) = peer_key.log2_distance(&enr.node_id().into()) {
                let ports_bucket = symmetric_nat_peers_ports.entry(distance).or_default();
                if ports_bucket.len() >= MAX_SYMMETRIC_NAT_PEERS_PER_KBUCKET {
                    warn!("Cannot insert peer {} behind a symmetric NAT into kbuckets. Limit of {} peers behind a symmetric NAT per kbucket reached", node_id, MAX_SYMMETRIC_NAT_PEERS_PER_KBUCKET);
                    return;
                }
                ports_bucket.insert(enr.node_id(), port);
            }

            debug!("Session established with node behind symmetric NAT: {}, direction: Incoming (always 'Incoming' for peer behind symmetric NAT)", node_id);
            self.connection_updated(
                node_id,
                ConnectionStatus::Connected(enr, ConnectionDirection::Incoming),
            );
        }
    }

    /// A session could not be established or an RPC request timed-out (after a few retries, if
    /// specified).
    fn rpc_failure(&mut self, id: RequestId, error: RequestError) {
        trace!("RPC Error removing request. Reason: {:?}, id {}", error, id);
        if let Some(active_request) = self.active_requests.remove(&id) {
            // If this is initiated by the user, return an error on the callback. All callbacks
            // support a request error.
            match active_request.callback {
                Some(CallbackResponse::Enr(callback)) => {
                    callback
                        .send(Err(error))
                        .unwrap_or_else(|_| debug!("Couldn't send TALK error response to user"));
                    return;
                }
                Some(CallbackResponse::Talk(callback)) => {
                    // return the error
                    callback
                        .send(Err(error))
                        .unwrap_or_else(|_| debug!("Couldn't send TALK error response to user"));
                    return;
                }
                None => {
                    // no callback to send too
                }
            }

            let node_id = active_request.contact.node_id();
            match active_request.request_body {
                // if a failed FindNodes request, ensure we haven't partially received packets. If
                // so, process the partially found nodes
                RequestBody::FindNode { .. } => {
                    if let Some(nodes_response) = self.active_nodes_responses.remove(&node_id) {
                        if !nodes_response.received_nodes.is_empty() {
                            warn!(
                                "NODES Response failed, but was partially processed from: {}",
                                active_request.contact
                            );
                            // if it's a query mark it as success, to process the partial
                            // collection of peers
                            self.discovered(
                                &active_request.contact,
                                nodes_response.received_nodes,
                                active_request.query_id,
                            );
                        }
                    } else {
                        // there was no partially downloaded nodes inform the query of the failure
                        // if it's part of a query
                        if let Some(query_id) = active_request.query_id {
                            if let Some(query) = self.queries.get_mut(query_id) {
                                query.on_failure(&node_id);
                            }
                        } else {
                            debug!(
                                "Failed RPC request: {}: {} ",
                                active_request.request_body, active_request.contact
                            );
                        }
                    }
                }
                // for all other requests, if any are queries, mark them as failures.
                _ => {
                    if let Some(query_id) = active_request.query_id {
                        if let Some(query) = self.queries.get_mut(query_id) {
                            debug!(
                                "Failed query request: {} for query: {} and {} ",
                                active_request.request_body, *query_id, active_request.contact
                            );
                            query.on_failure(&node_id);
                        }
                    } else {
                        debug!(
                            "Failed RPC request: {} for node: {}, reason {:?} ",
                            active_request.request_body, active_request.contact, error
                        );
                    }
                }
            }

            match error {
                RequestError::Timeout => {
                    match active_request.request_body {
                        RequestBody::RelayRequest { .. } => {}
                        _ => {
                            if self.local_enr.read().supports_nat() {
                                // Still drop the request and disconnect the peer but attempt
                                // establishing the connection to the peer via the NAT traversal
                                // protocol for sending future requests to the peer, if this peer
                                // was forwarded to us in a NODES response and we hence have a
                                // relay for it.
                                if let Some(relay) = active_request.relay {
                                    if let Some(relay_enr) = self.find_enr(&relay) {
                                        if let Some(relay_contact) =
                                            self.contact_from_enr(&relay_enr)
                                        {
                                            let local_enr = self.local_enr.read().clone();
                                            if let Some(enr) = active_request.contact.enr() {
                                                let to_node_id = enr.node_id();
                                                // Finish one relay request to a given peer before
                                                // starting another
                                                if let Entry::Vacant(e) =
                                                    self.receiver_enrs.entry(to_node_id)
                                                {
                                                    e.insert(enr);
                                                    _ = self.send_relay_request(
                                                        relay_contact,
                                                        local_enr,
                                                        to_node_id,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                RequestError::UnusedHolePunchPingToReceiver
                | RequestError::TimedOutHolePunchPing => {
                    // Don't update the connection if the request failed as expected according the
                    // NAT traversal protocol. A RequestError::UnusedHolePunchPingToReceiver means
                    // that a successful session has already been established. A
                    // RequestError::TimedOutHolePunchPing usually happens if both nodes are
                    // behind a NAT and this is the ping from the receiver to the initiator timing
                    // out but setting the entry in its router's state table for the initiator's
                    // hole punch ping coming next to enter.
                    return;
                }
                _ => {}
            }

            // If a request fails to send at Handler level or fails for some reason, remove the
            // belonging NAT traversal mappings if any.
            match active_request.request_body {
                RequestBody::RelayRequest { .. } => {
                    self.receiver_enrs.remove(&active_request.contact.node_id());
                }
                RequestBody::Ping { .. } => {
                    self.hole_punch_pings.remove(&node_id);
                }
                _ => {}
            }

            if let RequestBody::RelayRequest { ref from_enr, .. } = active_request.request_body {
                if from_enr.node_id() != self.local_enr.read().node_id() {
                    // This node is the rendezvous, return a RELAYRESPONSE to the
                    // initiator informing it of the error.
                    if let Some(relayed_request) = self.relayed_requests.remove(&id) {
                        self.send_relay_response(
                            relayed_request.initiator,
                            relayed_request.req_id_from_initiator,
                            RelayResponseCode::Error,
                        );
                    }
                }
            }

            self.connection_updated(node_id, ConnectionStatus::Disconnected);
        }
    }

    fn contact_from_enr(&self, enr: &Enr) -> Option<NodeContact> {
        if let Ok(contact) = NodeContact::try_from_enr(enr, self.config.ip_mode) {
            return Some(contact);
        } else if let Ok(contact) = NodeContact::try_from_enr_nat(enr, self.config.ip_mode) {
            return Some(contact);
        } else if let Some(ref symmetric_nat_peers_ports) = self.symmetric_nat_peers_ports {
            let node_id = enr.node_id();
            let peer_key: kbucket::Key<NodeId> = node_id.into();
            if let Some(distance) = peer_key.log2_distance(&enr.node_id().into()) {
                if let Some(ports_bucket) = symmetric_nat_peers_ports.get(&distance) {
                    if let Some(port) = ports_bucket.get(&node_id) {
                        match NodeContact::try_from_enr_nat_symmetric(
                            enr,
                            self.config.ip_mode,
                            *port,
                        ) {
                            Ok(contact) => {
                                return Some(contact);
                            }
                            Err(NonContactable { enr }) => {
                                warn!("ENR is non-contactable {}", enr);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// If this node is behind a NAT it is responsible for pinging its peers frequently enough to
    /// keep its NAT hole-punched for the bi-directional connection to the peer.
    fn update_peers_to_ping_nat(&mut self) {
        let mut peers_to_ping = HashSetDelay::new(PING_INTERVAL_NAT);
        for peer in self.peers_to_ping.iter() {
            peers_to_ping.insert(*peer);
        }
        self.peers_to_ping = peers_to_ping;
    }

    /// A future that maintains the routing table and inserts nodes when required. This returns the
    /// `Discv5Event::NodeInserted` variant if a new node has been inserted into the routing table.
    async fn bucket_maintenance_poll(
        kbuckets: &Arc<RwLock<KBucketsTable<NodeId, Enr>>>,
    ) -> Discv5Event {
        future::poll_fn(move |_cx| {
            // Drain applied pending entries from the routing table.
            if let Some(entry) = kbuckets.write().take_applied_pending() {
                let event = Discv5Event::NodeInserted {
                    node_id: entry.inserted.into_preimage(),
                    replaced: entry.evicted.map(|n| n.key.into_preimage()),
                };
                return Poll::Ready(event);
            }
            Poll::Pending
        })
        .await
    }

    /// A future the maintains active queries. This returns completed and timed out queries, as
    /// well as queries which need to be driven further with extra requests.
    async fn query_event_poll(queries: &mut QueryPool<QueryInfo, NodeId, Enr>) -> QueryEvent {
        future::poll_fn(move |_cx| match queries.poll() {
            QueryPoolState::Finished(query) => Poll::Ready(QueryEvent::Finished(Box::new(query))),
            QueryPoolState::Waiting(Some((query, return_peer))) => {
                let node_id = return_peer;
                let request_body = query.target().rpc_request(return_peer);
                Poll::Ready(QueryEvent::Waiting(query.id(), node_id, request_body))
            }
            QueryPoolState::Timeout(query) => {
                warn!("Query id: {:?} timed out", query.id());
                Poll::Ready(QueryEvent::TimedOut(Box::new(query)))
            }
            QueryPoolState::Waiting(None) | QueryPoolState::Idle => Poll::Pending,
        })
        .await
    }
}

/// The result of the `query_event_poll` indicating an action is required to further progress an
/// active query.
enum QueryEvent {
    /// The query is waiting for a peer to be contacted.
    Waiting(QueryId, NodeId, RequestBody),
    /// The query has timed out, possible returning peers.
    TimedOut(Box<crate::query_pool::Query<QueryInfo, NodeId, Enr>>),
    /// The query has completed successfully.
    Finished(Box<crate::query_pool::Query<QueryInfo, NodeId, Enr>>),
}

/// The types of queries that can be made.
pub enum QueryKind {
    /// A FindNode query. Searches for peers that are closest to a particular target.
    FindNode { target_node: NodeId },
    /// A predicate query. Searches for peers that are close to a target but filtered by a specific
    /// predicate and limited by a target peer count.
    Predicate {
        target_node: NodeId,
        target_peer_no: usize,
        predicate: Box<dyn Fn(&Enr) -> bool + Send>,
    },
}

/// Reporting the connection status of a node.
enum ConnectionStatus {
    /// A node has started a new connection with us.
    Connected(Enr, ConnectionDirection),
    /// We received a Pong from a new node. Do not have the connection direction.
    PongReceived(Enr),
    /// The node has disconnected
    Disconnected,
}
