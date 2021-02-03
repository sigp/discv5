//! The Discovery v5 protocol. See `lib.rs` for further details.
//!
//! Note: Discovered ENR's are not automatically added to the routing table. Only established
//! sessions get added, ensuring only valid ENRs are added. Manual additions can be made using the
//! `add_enr()` function.
//!
//! Response to queries return `PeerId`. Only the trusted (a session has been established with)
//! `PeerId`'s are returned, as ENR's for these `PeerId`'s are stored in the routing table and as
//! such should have an address to connect to. Untrusted `PeerId`'s can be obtained from the
//! `Service::Discovered` event, which is fired as peers get discovered.
//!
//! Note that although the ENR crate does support Ed25519 keys, these are currently not
//! supported as the ECDH procedure isn't specified in the specification. Therefore, only
//! secp256k1 keys are supported currently.

use self::{
    ip_vote::IpVote,
    query_info::{QueryInfo, QueryType},
};
use crate::{
    error::RequestError,
    handler::{Handler, HandlerRequest, HandlerResponse},
    kbucket::{self, ip_limiter, KBucketsTable, NodeStatus},
    node_info::{NodeAddress, NodeContact},
    packet::MAX_PACKET_SIZE,
    query_pool::{
        FindNodeQueryConfig, PredicateQueryConfig, QueryId, QueryPool, QueryPoolState, TargetKey,
    },
    rpc, Discv5Config, Discv5Event, Enr,
};
use enr::{CombinedKey, NodeId};
use fnv::FnvHashMap;
use futures::prelude::*;
use parking_lot::RwLock;
use rpc::*;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, task::Poll};
use tokio::{
    sync::{mpsc, oneshot},
    time::Interval,
};
use tracing::{debug, error, info, trace, warn};

mod ip_vote;
mod query_info;
mod test;

/// The number of distances (buckets) we simultaneously request from each peer.
pub(crate) const DISTANCES_TO_REQUEST_PER_PEER: usize = 3;

/// The types of requests to send to the Discv5 service.
pub enum ServiceRequest {
    StartQuery(QueryKind, oneshot::Sender<Vec<Enr>>),
    FindEnr(NodeContact, oneshot::Sender<Result<Enr, RequestError>>),
    Talk(
        NodeContact,
        Vec<u8>,
        Vec<u8>,
        oneshot::Sender<Result<Vec<u8>, RequestError>>,
    ),
    RequestEventStream(oneshot::Sender<mpsc::Receiver<Discv5Event>>),
}

use crate::discv5::PERMIT_BAN_LIST;

pub enum QueryKind {
    FindNode {
        target_node: NodeId,
    },
    Predicate {
        target_node: NodeId,
        target_peer_no: usize,
        predicate: Box<dyn Fn(&Enr) -> bool + Send>,
    },
}

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

    /// RPC requests that have been sent and are awaiting a response. Some requests are linked to a
    /// query.
    active_requests: FnvHashMap<RequestId, ActiveRequest>,

    /// Keeps track of the number of responses received from a NODES response.
    active_nodes_responses: HashMap<NodeId, NodesResponse>,

    /// A map of votes nodes have made about our external IP address. We accept the majority.
    ip_votes: Option<IpVote>,

    /// The channel to send messages to the handler.
    handler_send: mpsc::UnboundedSender<HandlerRequest>,

    /// The channel to receive messages from the handler.
    handler_recv: mpsc::Receiver<HandlerResponse>,

    /// The exit channel to shutdown the handler.
    handler_exit: Option<oneshot::Sender<()>>,

    /// The channel of messages sent by the controlling discv5 wrapper.
    discv5_recv: mpsc::Receiver<ServiceRequest>,

    /// The exit channel for the service.
    exit: oneshot::Receiver<()>,

    /// An interval to check and ping all nodes in the routing table.
    ping_heartbeat: Interval,

    /// A channel that the service emits events on.
    event_stream: Option<mpsc::Sender<Discv5Event>>,
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
    /// `local_enr` is the `ENR` representing the local node. This contains node identifying information, such
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
        let ip_votes = if config.enr_update {
            Some(IpVote::new(config.enr_peer_update_min))
        } else {
            None
        };

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
                    ip_votes,
                    handler_send,
                    handler_recv,
                    handler_exit: Some(handler_exit),
                    ping_heartbeat: tokio::time::interval(config.ping_interval),
                    discv5_recv,
                    event_stream: None,
                    exit,
                    config: config.clone(),
                };

                info!("Discv5 Service started");
                service.start().await;
            }));

        Ok((exit_send, discv5_send))
    }

    /// The main execution loop of the discv5 serviced.
    async fn start(&mut self) {
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
                        HandlerResponse::Established(enr) => {
                            self.inject_session_established(enr);
                        }
                        HandlerResponse::Request(node_address, request) => {
                                self.handle_rpc_request(node_address, *request);
                            }
                        HandlerResponse::Response(node_address, response) => {
                                self.handle_rpc_response(node_address, *response);
                            }
                        HandlerResponse::WhoAreYou(whoareyou_ref) => {
                            // check what our latest known ENR is for this node.
                            if let Some(known_enr) = self.find_enr(&whoareyou_ref.0.node_id) {
                                let _ = self.handler_send.send(HandlerRequest::WhoAreYou(whoareyou_ref, Some(known_enr)));
                            } else {
                                // do not know of this peer
                                debug!("NodeId unknown, requesting ENR. {}", whoareyou_ref.0);
                                let _ = self.handler_send.send(HandlerRequest::WhoAreYou(whoareyou_ref, None));
                            }
                        }
                        HandlerResponse::RequestFailed(request_id, error) => {
                            if let RequestError::Timeout = error {
                                debug!("RPC Request timed out. id: {}", request_id);
                            } else {
                                warn!("RPC Request failed: id: {}, error {:?}", request_id, error);
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
                            // obtain the ENR's for the resulting nodes
                            let mut found_enrs = Vec::new();
                            for node_id in result.closest_peers.into_iter() {
                                if let Some(position) = result.target.untrusted_enrs.iter().position(|enr| enr.node_id() == node_id) {
                                    let enr = result.target.untrusted_enrs.swap_remove(position);
                                    found_enrs.push(enr);
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
                _ = self.ping_heartbeat.tick() => {
                    self.ping_connected_peers();
                }
            }
        }
    }

    /// Internal function that starts a query.
    fn start_findnode_query(&mut self, target_node: NodeId, callback: oneshot::Sender<Vec<Enr>>) {
        let target = QueryInfo {
            query_type: QueryType::FindNode(target_node),
            untrusted_enrs: Default::default(),
            distances_to_request: DISTANCES_TO_REQUEST_PER_PEER,
            callback,
        };

        let target_key: kbucket::Key<NodeId> = target.key();
        let known_closest_peers: Vec<kbucket::Key<NodeId>> = {
            let mut kbuckets = self.kbuckets.write();
            kbuckets.closest_keys(&target_key).collect()
        };
        let query_config = FindNodeQueryConfig::new_from_config(&self.config);
        self.queries
            .add_findnode_query(query_config, target, known_closest_peers);
    }

    /// Internal function that starts a query.
    fn start_predicate_query(
        &mut self,
        target_node: NodeId,
        num_nodes: usize,
        predicate: Box<dyn Fn(&Enr) -> bool + Send>,
        callback: oneshot::Sender<Vec<Enr>>,
    ) {
        let target = QueryInfo {
            query_type: QueryType::FindNode(target_node),
            untrusted_enrs: Default::default(),
            distances_to_request: DISTANCES_TO_REQUEST_PER_PEER,
            callback,
        };

        let target_key: kbucket::Key<NodeId> = target.key();

        let known_closest_peers: Vec<kbucket::PredicateKey<NodeId>> = {
            let mut kbuckets = self.kbuckets.write();
            kbuckets
                .closest_keys_predicate(&target_key, &predicate)
                .collect()
        };

        let mut query_config = PredicateQueryConfig::new_from_config(&self.config);
        query_config.num_results = num_nodes;
        self.queries
            .add_predicate_query(query_config, target, known_closest_peers, predicate);
    }

    /// Returns an ENR if one is known for the given NodeId.
    pub fn find_enr(&mut self, node_id: &NodeId) -> Option<Enr> {
        // check if we know this node id in our routing table
        let key = kbucket::Key::from(*node_id);
        if let kbucket::Entry::Present(mut entry, _) = self.kbuckets.write().entry(&key) {
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
                            to_request_enr = Some(enr.into());
                        }
                    }
                    kbucket::Entry::Pending(ref mut entry, _) => {
                        if entry.value().seq() < enr_seq {
                            let enr = entry.value().clone();
                            to_request_enr = Some(enr.into());
                        }
                    }
                    // don't know of the ENR, request the update
                    _ => {}
                }
                if let Some(enr) = to_request_enr {
                    self.request_enr(enr, None);
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
                let _ = self
                    .handler_send
                    .send(HandlerRequest::Response(node_address, Box::new(response)));
            }
            RequestBody::Talk { protocol, request } => {
                // Send the callback's response to this protocol.
                let response = (self.config.talkreq_callback)(&protocol, &request);
                let response = Response {
                    id,
                    body: ResponseBody::Talk { response },
                };

                debug!("Sending TALK response to {}", node_address);
                let _ = self
                    .handler_send
                    .send(HandlerRequest::Response(node_address, Box::new(response)));
            }
            RequestBody::RegisterTopic { .. } => {
                debug!("Received RegisterTopic request which is unimplemented");
            }
            RequestBody::TopicQuery { .. } => {
                debug!("Received TopicQuery request which is unimplemented");
            }
        }
    }

    /// Processes an RPC response from a peer.
    fn handle_rpc_response(&mut self, node_address: NodeAddress, response: Response) {
        // verify we know of the rpc_id
        let id = response.id.clone();

        if let Some(mut active_request) = self.active_requests.remove(&id) {
            debug!(
                "Received RPC response: {} to request: {} from: {}",
                response.body, active_request.request_body, active_request.contact
            );

            // Check that the responder matches the expected request
            if let Ok(request_node_address) = active_request.contact.node_address() {
                if request_node_address != node_address {
                    warn!("Received a response from an unexpected address. Expected {}, received {}, request_id {}", request_node_address, node_address, id);
                    return;
                }
            }

            let node_id = active_request.contact.node_id();
            if !response.match_request(&active_request.request_body) {
                warn!(
                    "Node gave an incorrect response type. Ignoring response from: {}",
                    active_request.contact
                );
                return;
            }
            match response.body {
                ResponseBody::Nodes { total, mut nodes } => {
                    // Currently a maximum of DISTANCES_TO_REQUEST_PER_PEER*BUCKET_SIZE peers can be returned. Datagrams have a max
                    // size of 1280 and ENR's have a max size of 300 bytes.
                    //
                    // Bucket sizes should be 16. In this case, there should be no more than 5*DISTANCES_TO_REQUEST_PER_PEER responses, to return all required peers.
                    if total > 5 * DISTANCES_TO_REQUEST_PER_PEER as u64 {
                        warn!(
                            "NodesResponse has a total larger than {}, nodes will be truncated",
                            DISTANCES_TO_REQUEST_PER_PEER * 5
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
                        // Currently only support requesting for ENR's. Verify this is the case.
                        if !distances_requested.is_empty() && distances_requested[0] != 0 {
                            error!("Retrieved a callback request that wasn't for a peer's ENR");
                            return;
                        }
                        // This must be for asking for an ENR
                        if nodes.len() > 1 {
                            warn!(
                                "Peer returned more than one ENR for itself. {}",
                                active_request.contact
                            );
                        }
                        let response = nodes.pop().ok_or_else(|| {
                            RequestError::InvalidEnr("Peer did not return an ENR".into())
                        });
                        let _ = callback.send(response);
                        return;
                    }

                    // Filter out any nodes that are not of the correct distance
                    let peer_key: kbucket::Key<NodeId> = node_id.into();

                    // The distances we send are sanitized an ordered.
                    // We never send an ENR request in combination of other requests.
                    if distances_requested.len() == 1 && distances_requested[0] == 0 {
                        // we requested an ENR update
                        if nodes.len() > 1 {
                            warn!(
                                "Peer returned more than one ENR for itself. Blacklisting {}",
                                active_request.contact
                            );
                        }
                        PERMIT_BAN_LIST.write().ban(
                            active_request
                                .contact
                                .node_address()
                                .expect("Sanitized request"),
                        );
                        nodes.retain(|enr| {
                            peer_key
                                .log2_distance(&enr.node_id().clone().into())
                                .is_none()
                        });
                    } else {
                        let before_len = nodes.len();
                        nodes.retain(|enr| {
                            peer_key
                                .log2_distance(&enr.node_id().clone().into())
                                .map(|distance| distances_requested.contains(&distance))
                                .unwrap_or_else(|| false)
                        });

                        if nodes.len() < before_len {
                            // Peer sent invalid ENRs. Blacklist the Node
                            warn!(
                                "Peer sent invalid ENR. Blacklisting {}",
                                active_request.contact
                            );
                            PERMIT_BAN_LIST.write().ban(
                                active_request
                                    .contact
                                    .node_address()
                                    .expect("Sanitized request"),
                            );
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
                        // if there are more requests coming, store the nodes and wait for
                        // another response
                        // We allow for implementations to send at a minimum 3 nodes per response.
                        // We allow for the number of nodes to be returned as the maximum we emit.
                        if current_response.count < self.config.max_nodes_response / 3 + 1
                            && (current_response.count as u64) < total
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
                        active_request.contact
                    );
                    // note: If a peer sends an initial NODES response with a total > 1 then
                    // in a later response sends a response with a total of 1, all previous nodes
                    // will be ignored.
                    // ensure any mapping is removed in this rare case
                    self.active_nodes_responses.remove(&node_id);

                    self.discovered(&node_id, nodes, active_request.query_id);
                }
                ResponseBody::Pong { enr_seq, ip, port } => {
                    let socket = SocketAddr::new(ip, port);
                    // perform ENR majority-based update if required.
                    let local_socket = self.local_enr.read().udp_socket();
                    if let Some(ref mut ip_votes) = self.ip_votes {
                        ip_votes.insert(node_id, socket);
                        if let Some(majority_socket) = ip_votes.majority() {
                            if Some(majority_socket) != local_socket {
                                info!("Local UDP socket updated to: {}", majority_socket);
                                self.send_event(Discv5Event::SocketUpdated(majority_socket));
                                // Update the UDP socket
                                if self
                                    .local_enr
                                    .write()
                                    .set_udp_socket(majority_socket, &self.enr_key.read())
                                    .is_ok()
                                {
                                    // alert known peers to our updated enr
                                    self.ping_connected_peers();
                                }
                            }
                        }
                    }

                    // check if we need to request a new ENR
                    if let Some(enr) = self.find_enr(&node_id) {
                        if enr.seq() < enr_seq {
                            // request an ENR update
                            debug!("Requesting an ENR update from: {}", active_request.contact);
                            let request_body = RequestBody::FindNode { distances: vec![0] };
                            let active_request = ActiveRequest {
                                contact: active_request.contact,
                                request_body,
                                query_id: None,
                                callback: None,
                            };
                            self.send_rpc_request(active_request);
                        }
                        self.connection_updated(node_id, Some(enr), NodeStatus::Connected);
                    }
                }
                ResponseBody::Talk { response } => {
                    // Send the response to the user
                    match active_request.callback {
                        Some(CallbackResponse::Talk(callback)) => {
                            let _ = callback.send(Ok(response));
                        }
                        _ => error!("Invalid callback for response"),
                    }
                }
                ResponseBody::Ticket { .. } => {
                    error!("Received a TICKET response. This is unimplemented and should be unreachable.");
                }
                ResponseBody::RegisterConfirmation { .. } => {
                    error!("Received a RegisterConfirmation response. This is unimplemented and should be unreachable.");
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
    fn send_ping(&mut self, enr: Enr) {
        let request_body = RequestBody::Ping {
            enr_seq: self.local_enr.read().seq(),
        };
        let active_request = ActiveRequest {
            contact: enr.into(),
            request_body,
            query_id: None,
            callback: None,
        };
        self.send_rpc_request(active_request);
    }

    fn ping_connected_peers(&mut self) {
        // maintain the ping interval
        let connected_peers = {
            let mut kbuckets = self.kbuckets.write();
            kbuckets
                .iter()
                .filter_map(|entry| {
                    if entry.status == NodeStatus::Connected {
                        Some(entry.node.value.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };

        for enr in connected_peers {
            self.send_ping(enr.clone());
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
        };
        self.send_rpc_request(active_request);
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
        };
        self.send_rpc_request(active_request);
    }

    /// Sends a NODES response, given a list of found ENR's. This function splits the nodes up
    /// into multiple responses to ensure the response stays below the maximum packet size.
    fn send_nodes_response(
        &mut self,
        node_address: NodeAddress,
        rpc_id: RequestId,
        mut distances: Vec<u64>,
    ) {
        // NOTE: At most we only allow 5 distances to be send (see the decoder). If each of these
        // buckets are full, that equates to 80 ENR's to respond with.

        let mut nodes_to_send = Vec::new();
        distances.sort_unstable();
        distances.dedup();

        if let Some(0) = distances.first() {
            // if the distance is 0 send our local ENR
            nodes_to_send.push(self.local_enr.read().clone());
            debug!("Sending our ENR to node: {}", node_address);
            distances.remove(0);
        }

        if !distances.is_empty() {
            let mut kbuckets = self.kbuckets.write();
            for node in kbuckets
                .nodes_by_distances(distances, self.config.max_nodes_response)
                .into_iter()
                .filter_map(|entry| {
                    if entry.node.key.preimage() != &node_address.node_id {
                        Some(entry.node.value.clone())
                    } else {
                        None
                    }
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
            let _ = self
                .handler_send
                .send(HandlerRequest::Response(node_address, Box::new(response)));
        } else {
            // build the NODES response
            let mut to_send_nodes: Vec<Vec<Enr>> = Vec::new();
            let mut total_size = 0;
            let mut rpc_index = 0;
            to_send_nodes.push(Vec::new());
            for enr in nodes_to_send.into_iter() {
                let entry_size = rlp::encode(&enr).len();
                // Responses assume that a session is established. Thus, on top of the encoded
                // ENR's the packet should be a regular message. A regular message has an IV (16
                // bytes), and a header of 55 bytes. The find-nodes RPC requires 16 bytes for the ID and the
                // `total` field. Also there is a 16 byte HMAC for encryption and an extra byte for
                // RLP encoding.
                //
                // We could also be responding via an autheader which can take up to 282 bytes in its
                // header.
                // As most messages will be normal messages we will try and pack as many ENR's we
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
                let _ = self.handler_send.send(HandlerRequest::Response(
                    node_address.clone(),
                    Box::new(response),
                ));
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
            let active_request = ActiveRequest {
                contact: enr.into(),
                request_body,
                query_id: Some(query_id),
                callback: None,
            };
            self.send_rpc_request(active_request);
        } else {
            error!("Query {} requested an unknown ENR", *query_id);
        }
    }

    /// Sends generic RPC requests. Each request gets added to known outputs, awaiting a response.
    fn send_rpc_request(&mut self, active_request: ActiveRequest) {
        // Generate a random rpc_id which is matched per node id
        let id = RequestId::random();
        let request: Request = Request {
            id: id.clone(),
            body: active_request.request_body.clone(),
        };
        let contact = active_request.contact.clone();
        self.active_requests.insert(id, active_request);
        debug!("Sending RPC {} to node: {}", request, contact);

        let _ = self
            .handler_send
            .send(HandlerRequest::Request(contact, Box::new(request)));
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
    fn discovered(&mut self, source: &NodeId, enrs: Vec<Enr>, query_id: Option<QueryId>) {
        let local_id = self.local_enr.read().node_id();
        let other_enr_iter = enrs.iter().filter(|p| p.node_id() != local_id);

        for enr_ref in other_enr_iter.clone() {
            // If any of the discovered nodes are in the routing table, and there contains an older ENR, update it.
            // If there is an event stream send the Discovered event
            if self.config.report_discovered_peers {
                self.send_event(Discv5Event::Discovered(enr_ref.clone()));
            }

            // ignore peers that don't pass the table filter
            if (self.config.table_filter)(enr_ref) {
                let key = kbucket::Key::from(enr_ref.node_id());
                if !self.config.ip_limit
                    || self
                        .kbuckets
                        .read()
                        .check(&key, enr_ref, |v, o, l| ip_limiter(v, &o, l))
                {
                    match self.kbuckets.write().entry(&key) {
                        kbucket::Entry::Present(mut entry, _) => {
                            if entry.value().seq() < enr_ref.seq() {
                                trace!("ENR updated: {}", enr_ref);
                                *entry.value() = enr_ref.clone();
                            }
                        }
                        kbucket::Entry::Pending(mut entry, _) => {
                            if entry.value().seq() < enr_ref.seq() {
                                trace!("ENR updated: {}", enr_ref);
                                *entry.value() = enr_ref.clone();
                            }
                        }
                        kbucket::Entry::Absent(_entry) => {}
                        _ => {}
                    }
                }
            }
        }

        // if this is part of a query, update the query
        if let Some(query_id) = query_id {
            if let Some(query) = self.queries.get_mut(query_id) {
                let mut peer_count = 0;
                for enr_ref in other_enr_iter.clone() {
                    if query
                        .target_mut()
                        .untrusted_enrs
                        .iter()
                        .position(|e| e.node_id() == enr_ref.node_id())
                        .is_none()
                    {
                        query.target_mut().untrusted_enrs.push(enr_ref.clone());
                    }
                    peer_count += 1;
                }
                debug!("{} peers found for query id {:?}", peer_count, query_id);
                query.on_success(source, &other_enr_iter.cloned().collect::<Vec<_>>())
            } else {
                warn!("Response returned for ended query {:?}", query_id)
            }
        }
    }

    /// Update the connection status of a node in the routing table.
    fn connection_updated(
        &mut self,
        node_id: NodeId,
        enr: Option<Enr>,
        mut new_status: NodeStatus,
    ) {
        let key = kbucket::Key::from(node_id);
        if let Some(enr) = enr.as_ref() {
            // ignore peers that don't pass the table filter
            if !(self.config.table_filter)(enr) {
                return;
            }

            // should the ENR be inserted or updated to a value that would exceed the IP limit ban
            if self.config.ip_limit
                && !self
                    .kbuckets
                    .read()
                    .check(&key, enr, |v, o, l| ip_limiter(v, &o, l))
            {
                // if the node status is connected and it would exceed the ip ban, consider it
                // disconnected to be pruned.
                new_status = NodeStatus::Disconnected;
            }
        }

        let mut event_to_send = None;
        let mut ping_peer = None;
        match self.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(mut entry, old_status) => {
                if let Some(enr) = enr {
                    *entry.value() = enr;
                }
                if old_status != new_status {
                    entry.update(new_status);
                }
            }
            kbucket::Entry::Pending(mut entry, old_status) => {
                if let Some(enr) = enr {
                    *entry.value() = enr;
                }
                if old_status != new_status {
                    entry.update(new_status);
                }
            }
            kbucket::Entry::Absent(entry) => {
                if new_status == NodeStatus::Connected {
                    // Note: If an ENR is not provided, no record is added
                    debug_assert!(enr.is_some());
                    if let Some(enr) = enr {
                        match entry.insert(enr, new_status) {
                            kbucket::InsertResult::Inserted => {
                                let event = Discv5Event::NodeInserted {
                                    node_id,
                                    replaced: None,
                                };
                                event_to_send = Some(event);
                            }
                            kbucket::InsertResult::Full => (),
                            kbucket::InsertResult::Pending { disconnected } => {
                                ping_peer = Some(*disconnected.preimage());
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        if let Some(event) = event_to_send {
            self.send_event(event);
        }
        if let Some(node_id) = ping_peer {
            if let Some(enr) = self.find_enr(&node_id) {
                self.send_ping(enr);
            }
        }
    }

    /// The equivalent of libp2p `inject_connected()` for a udp session. We have no stream, but a
    /// session key-pair has been negotiated.
    fn inject_session_established(&mut self, enr: Enr) {
        // Ignore sessions with non-contactable ENRs
        if enr.udp_socket().is_none() {
            return;
        }

        let node_id = enr.node_id();
        debug!("Session established with Node: {}", node_id);
        self.connection_updated(node_id, Some(enr.clone()), NodeStatus::Connected);
        // send an initial ping and start the ping interval
        self.send_ping(enr);
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
                                &node_id,
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

            self.connection_updated(node_id, None, NodeStatus::Disconnected);
        }
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

                let request_body = match query.target().rpc_request(&return_peer) {
                    Ok(r) => r,
                    Err(e) => {
                        // dst node is local_key, report failure
                        error!("Send RPC failed: {}", e);
                        query.on_failure(&node_id);
                        return Poll::Pending;
                    }
                };

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
