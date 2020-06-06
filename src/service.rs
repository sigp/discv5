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

use self::ip_vote::IpVote;
use self::query_info::{QueryInfo, QueryType};
use crate::error::ServiceError;
use crate::handler::{Handler, HandlerRequest, HandlerResponse};
use crate::kbucket::{self, EntryRefView, KBucketsTable, NodeStatus};
use crate::node_info::{NodeAddress, NodeContact};
use crate::query_pool::{
    FindNodeQueryConfig, PredicateQueryConfig, QueryId, QueryPool, QueryPoolState, ReturnPeer,
};
use crate::rpc;
use crate::socket::MAX_PACKET_SIZE;
use crate::Enr;
use enr::{CombinedKey, EnrError, EnrKey, NodeId};
use fnv::FnvHashMap;
use futures::prelude::*;
use log::{debug, error, info, trace, warn};
use parking_lot::RwLock;
use rpc::*;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use crate::Discv5Event;

mod ip_vote;
mod query_info;
// mod test;


/// The types of requests to send to the Discv5 service.
pub enum ServiceRequest {
    StartQuery(QueryType, oneshot::Sender<Vec<Enr>>),
    FindEnr(NodeContact, oneshot::Sender<Option<Enr>>),
    RequestEventStream(oneshot::Sender<mpsc::Receiver<Discv5Event>>),
}

pub enum QueryType {
    FindNode {
        target_node: NodeId,
    },
    Predicate {
        target_node: NodeId,
        target_peer_no: usize,
        predicate: Box<dyn Fn(&Enr) -> bool>,
    },
}




// TODO: ENR's for connected peer should be maintained.
pub struct Service {
    /// Configuration parameters.
    config: Discv5Config,

    /// The local ENR of the server.
    local_enr: Arc<RwLock<Enr>>,

    /// The key associated with the local ENR.
    enr_key: Arc<RwLock<CombinedKey>>,

    /// Storage of the ENR record for each node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Enr>>,

    /// All the iterative queries we are currently performing.
    queries: QueryPool<QueryInfo, NodeId, Enr>,

    /// RPC requests that have been sent and are awaiting a response. Some requests are linked to a
    /// query.
    active_rpc_requests: FnvHashMap<RequestId, ActiveRequest>,

    /// Keeps track of the number of responses received from a NODES response.
    active_nodes_responses: HashMap<NodeAddress, NodesResponse>,

    /// A map of votes nodes have made about our external IP address. We accept the majority.
    ip_votes: Option<IpVote>,

    /// The channel to send messages to the handler.
    handler_send: mpsc::Sender<HandlerRequest>,

    /// The channel to receive messages from the handler.
    handler_recv: mpsc::Receiver<HandlerResponse>,

    /// The exit channel to shutdown the handler.
    handler_exit: Option<oneshot::Sender<()>>,

    discv5_recv: mspc::Receiver<ServiceRequest>,

    exit: oneshot::Receiver<()>,
    /// An interval to check and ping all nodes in the routing table.
    ping_heartbeat: Interval,

    event_stream: Option<mpsc::Sender<Discv5Event>>
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
    pub callback_id: Option<u64>,
}

impl ActiveRequest {
    pub fn is_query(&self) -> bool {
        self.query_id.is_some()
    }
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
    pub fn spawn(
        local_enr: Arc<RwLock<Enr>>,
        enr_key: Arc<RwLock<CombinedKey>>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Enr>>,
        mut config: Discv5Config,
        listen_socket: SocketAddr,
    ) -> (oneshot::Sender<()>, mpsc::Sender<ServiceRequest>) {

        let node_id = local_enr.node_id();

        // process behaviour-level configuration parameters
        let ip_votes = if config.enr_update {
            Some(IpVote::new(config.enr_peer_update_min))
        } else {
            None
        };

        // build the session service
        let (handler_exit, handler_send, handler_recv) = Handler::spawn(
            self.local_enr.clone(),
            self.enr_key.clone(),
            listen_socket,
            &self.config,
        );

        // create the required channels
        let (discv5_send, discv5_recv) = mpsc::channel(30);
        let (exit_send, exit) = oneshot::channel();


        let mut service = Service {
            local_enr,
            enr_key,
            kbuckets:
            queries: QueryPool::new(config.query_timeout.clone()),
            active_rpc_requests: Default::default(),
            active_nodes_responses: HashMap::new(),
            ip_votes,
            connected_peers: Default::default(),
            handler_send,
            handler_recv,
            handler_exit,
            ping_heartbeat: tokio::time::interval(config.ping_interval),
            discv5_recv,
            event_stream: None,
            exit,
            config.clone(),
        };

        config
            .executor
            .clone()
            .expect("Executor must be present")
            .spawn(Box::pin(async move {
                info!("Discv5 Service started");
                handler.start().await;
            }));

        (exit_send, discv5_send)
    }

    /// The main execution loop of the discv5 serviced.
    async fn start(&mut self) {
        loop {
            tokio::select! {
                _ = &mut self.exit => {
                    let _ = exit.send(());
                    info!("Discv5 Service shutdown");
                }
                Some(service_request) = &mut self.discv5_recv => {
                    match service_request {
                        StartQuery(query, callback) => {
                            match query {
                                QueryType::FindNode { target_node } => {
                                    self.start_findnode_query(target_node, callback);
                                }
                                QueryType::Predicate { target_node, target_peer_no, predicate } => {
                                    self.start_predicate_query(target_node, target_peer_no, predicate, callback);
                                }
                            }
                        }
                        FindEnr(node_contact, callback) => {
                            self.request_enr(node_contact, Some(callback)).await;
                        }
                        RequestEventStream(callback) => {
                            let (event_stream, event_stream_recv) = mpsc::channel(30);
                            self.event_stream = Some(event_stream);
                            if let Err(e) = callback.send(event_stream_recv) {
                                error!("Failed to return the event stream channel");
                            }
                        }
                    }
                }
                Some(event) = &mut self.handler_recv.next() => {
                    match event {
                        HandlerResponse::Established(enr) => {
                            self.inject_session_established(enr);
                        }
                        HandlerResponse::Request(node_address, request) => {
                                self.handle_rpc_request(node_address, request).await;
                            }
                        HandlerResponse::Response(_, response) => {
                                self.handle_rpc_response(response).await;
                            }
                        HandlerResponse::WhoAreYou(whoareyou_ref) => {
                            // check what our latest known ENR is for this node.
                            if let Some(known_enr) = self.find_enr(&whoareyou_ref.0.node_id) {
                                self.send_to_handler(HandlerRequest::WhoAreYou(whoareyou_ref, Some(known_enr))).await;
                            } else {
                                // do not know of this peer
                                debug!("NodeId unknown, requesting ENR. {}", whoareyou_ref.0);
                                self.send_to_handler(HandlerRequest::WhoAreYou(whoareyou_ref, None)).await;
                            }
                        }
                        HandlerResponse::RequestFailed(request_id, error) => {
                            trace!("RPC Request failed: id: {}, error {:?}", request_id, error);
                            self.rpc_failure(request_id);
                        }
                    }
                }
                event = Service::bucket_maintenance_poll(&mut self.kbuckets) => {
                    self.send_event_stream(event).await;
                }
                query_event = Service::query_event_poll(&mut self.queries) => {
                    match query_event {
                        QueryEvent::Waiting(query_id, target, return_peer) => {
                            self.send_rpc_query(query_id, target, &return_peer).await;
                        }
                        // Note: Currently the distinction between a timed-out query and a finished
                        // query is superfluous, however it may be useful in future versions.
                        QueryEvent::Finished(query) => {
                                if let Err(e) = query.target.callback.send(Ok(qeuery.into_result())).await {
                                    warn!("Callback dropped for query {}. Results dropped", query_id);
                                }
                        }
                        QueryEvent::TimedOut(query) => {
                                if let Err(e) = query.target.callback.send(Ok(qeuery.into_result())).await {
                                    warn!("Callback dropped for query {}. Results dropped", query_id);
                                }
                        }
                    }
                }
                _ = self.ping_heartbeat.next() => {
                    self.ping_connected_peers().await;
            }
    }


    /// Internal function that starts a query.
    fn start_findnode_query(&mut self, target_node: NodeId, callback: oneshot::Sender<Vec<Enr>>) {
        let target = QueryInfo {
            query_type: QueryType::FindNode(target_node),
            untrusted_enrs: Default::default(),
            callback,
        };

        // How many times to call the rpc per node.
        // FINDNODE requires multiple iterations as it requests a specific distance.
        let query_iterations = target.iterations();

        let target_key: kbucket::Key<QueryInfo> = target.clone().into();
        let known_closest_peers = self.kbuckets.closest_keys(&target_key);
        let query_config = FindNodeQueryConfig::new_from_config(&self.config);
        self.queries
            .add_findnode_query(query_config, target, known_closest_peers, query_iterations)
    }

    /// Internal function that starts a query.
    fn start_predicate_query<F>(
        &mut self,
        target_node: NodeId,
        num_nodes: usize,
        predicate: F,
        callback: oneshot::Sender<Vec<Enr>>,
    ) 
    where
        F: Fn(&Enr) -> bool + Send + Clone + 'static,
    {
        let target = QueryInfo {
            query_type: QueryType::FindNode(target_node),
            untrusted_enrs: Default::default(),
            callback,
        };

        // How many times to call the rpc per node.
        // FINDNODE requires multiple iterations as it requests a specific distance.
        let query_iterations = target.iterations();

        let target_key: kbucket::Key<QueryInfo> = target.clone().into();

        let known_closest_peers = self
            .kbuckets
            .closest_keys_predicate(&target_key, predicate.clone());

        let mut query_config = PredicateQueryConfig::new_from_config(&self.config);
        query_config.num_results = num_nodes;
        self.queries.add_predicate_query(
            query_config,
            target,
            known_closest_peers,
            query_iterations,
            predicate,
        )
    }

    /// Processes an RPC request from a peer. Requests respond to the received socket address,
    /// rather than the IP of the known ENR.
    async fn handle_rpc_request(&mut self, node_address: NodeAddress, req: Request) {
        let id = req.id;
        match req.body {
            RequestBody::FindNode { distance } => {
                // if the distance is 0 send our local ENR
                if distance == 0 {
                    let response = Response {
                        id,
                        body: ResponseBody::Nodes {
                            total: 1,
                            nodes: vec![self.local_enr().clone()],
                        },
                    };
                    debug!("Sending our ENR to node: {}", node_address);
                    self.handler_send(HandlerRequest::Response(node_address, response))
                        .await.unwrap_or_else(|| ());
                } else {
                    self.send_nodes_response(node_address, id, distance).await;
                }
            }
            RequestBody::Ping { enr_seq } => {
                // check if we need to update the known ENR
                match self.kbuckets.entry(&node_address.node_id.into()) {
                    kbucket::Entry::Present(ref mut entry, _) => {
                        if entry.value().seq() < enr_seq {
                            let enr = entry.value().clone();
                            self.request_enr(enr.into()).await;
                        }
                    }
                    kbucket::Entry::Pending(ref mut entry, _) => {
                        if entry.value().seq() < enr_seq {
                            let enr = entry.value().clone();
                            self.request_enr(enr.into()).await;
                        }
                    }
                    // don't know of the ENR, request the update
                    _ => {
                        // The ENR is no longer in our table, we stop responding to PING's
                        return;
                    }
                }

                // build the PONG response
                let src = node_address.socket_addr.clone();
                let response = Response {
                    id,
                    body: ResponseBody::Ping {
                        enr_seq: self.local_enr().seq(),
                        ip: src.ip(),
                        port: src.port(),
                    },
                };
                debug!("Sending PONG response to {}", node_address);
                self.handler_send(HandlerRequest::Response(node_address, response))
                    .await.unwrap_or_else(|| ());
            }
            _ => {} //TODO: Implement all RPC methods
        }
    }

    /// Processes an RPC response from a peer.
    async fn handle_rpc_response(&mut self, response: Response) {
        // verify we know of the rpc_id
        let id = response.id;

        if let Some(active_request) = self.active_rpc_requests.remove(&id) {
            if !response.match_request(&request) {
                warn!(
                    "Node gave an incorrect response type. Ignoring response from: {}",
                    node_address
                );
                return;
            }
            match response.body {
                ResponseBody::Nodes { total, mut nodes } => {
                    // Currently a maximum of 16 peers can be returned. Datagrams have a max
                    // size of 1280 and ENR's have a max size of 300 bytes. There should be no
                    // more than 5 responses, to return 16 peers.
                    if total > 5 {
                        warn!("NodesResponse has a total larger than 5, nodes will be truncated");
                    }

                    let distance_requested = match request {
                        RequestBody::FindNode { distance } => distance,
                        _ => unreachable!(),
                    };

                    // This could be an ENR request from the outer service. If so respond to the
                    // callback and End.
                    if let Some(id) = active_request.callback_id {
                        // Currently only support requesting for ENR's. Verify this is the case.
                        if distance_request != 0 {
                            crit!("Retrieved a callback request that wasn't for a peer's ENR");
                            return;
                        }
                        if let Some(callback) = self.active_callbacks.remove(id) {
                            // This must be for asking for an ENR
                            if let nodes.len() > 1 {
                                warn!("Peer returned more than one ENR for itself. {}", node_address);
                            }
                            callback.send(nodes.pop()).await.unwrap_or_else(|| ());
                            return;
                        }
                    }

                    // Filter out any nodes that are not of the correct distance
                    // TODO: Blacklist and remove peers that have the incorrect distance
                    let peer_key: kbucket::Key<NodeId> = node_address.node_id.into();
                    let distance_requested = match request {
                        RequestBody::FindNode { distance } => distance,
                        _ => unreachable!(),
                    };
                    if distance_requested != 0 {
                        nodes.retain(|enr| {
                            peer_key.log2_distance(&enr.node_id().clone().into())
                                == Some(distance_requested)
                        });
                    } else {
                        // requested an ENR update
                        nodes.retain(|enr| {
                            peer_key
                                .log2_distance(&enr.node_id().clone().into())
                                .is_none()
                        });
                    }

                    // handle the case that there is more than one response
                    if total > 1 {
                        let mut current_response = self
                            .active_nodes_responses
                            .remove(&node_address.node_id)
                            .unwrap_or_default();

                        debug!(
                            "Nodes Response: {} of {} received",
                            current_response.count, total
                        );
                        // if there are more requests coming, store the nodes and wait for
                        // another response
                        if current_response.count < 5 && (current_response.count as u64) < total {
                            current_response.count += 1;

                            current_response.received_nodes.append(&mut nodes);
                            self.active_nodes_responses
                                .insert(node_address.node_id, current_response);
                            self.active_rpc_requests
                                .insert(id, (query_id, request, node_address));
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
                        node_address
                    );
                    // note: If a peer sends an initial NODES response with a total > 1 then
                    // in a later response sends a response with a total of 1, all previous nodes
                    // will be ignored.
                    // ensure any mapping is removed in this rare case
                    self.active_nodes_responses.remove(&node_address.node_id);

                    self.discovered(&node_address.node_id, nodes, query_id);
                }
                ResponseBody::Ping { enr_seq, ip, port } => {
                    let socket = SocketAddr::new(ip, port);
                    // perform ENR majority-based update if required.
                    let local_socket = self.local_enr().udp_socket();
                    if let Some(ref mut ip_votes) = self.ip_votes {
                        ip_votes.insert(node_address.node_id, socket.clone());
                        let majority_socket = ip_votes.majority();
                        if majority_socket.is_some() && majority_socket != local_socket {
                            let majority_socket = majority_socket.expect("is some");
                            info!("Local UDP socket updated to: {}", majority_socket);
                            self.discv5_events
                                .push_back(ServiceEvent::SocketUpdated(majority_socket));
                            if self.update_local_enr_socket(majority_socket, false) {
                                // alert known peers to our updated enr
                                self.ping_connected_peers();
                            }
                        }
                    }

                    // check if we need to request a new ENR
                    if let Some(enr) = self.find_enr(&node_address.node_id) {
                        if enr.seq() < enr_seq {
                            // request an ENR update
                            debug!("Requesting an ENR update from: {}", node_address);
                            let request_body = RequestBody::FindNode { distance: 0 };
                            self.send_rpc_request(&enr.node_id(), request_body, None)
                                .await;
                        }
                        self.connection_updated(
                            node_address.node_id,
                            Some(enr),
                            NodeStatus::Connected,
                        )
                    }
                }
                _ => {} //TODO: Implement all RPC methods
            }
        } else {
            warn!("Received an RPC response which doesn't match a request");
        }
    }

    // Send RPC Requests //

    /// Sends a PING request to a node.
    async fn send_ping(&mut self, enr: Enr) {
        let request_body = RequestBody::Ping {
            enr_seq: self.local_enr.read().seq(),
        };
        let active_request = ActiveRequest {
            contact: enr.into(),
            request_body,
            query_id: None,
            callback_id: None,
        };
        self.send_rpc_request(active_request).await;
    }

    async fn ping_connected_peers(&mut self) {
        // maintain the ping interval
        let connected_peers = self.kbuckets.write().iter().filter_map(|entry| {
            if entry.status = NodeStatus::Connected {
                Some(entry.node.value)
                } else { None }
        }).collect::Vec<_>();

        for enr in connected_peers {
            self.send_ping(enr).await;
        }
    }

    /// Request an external node's ENR.
    async fn request_enr(&mut self, contact: NodeContact, callback: Option<oneshot::channel<Option<Enr>>) {
        let request = RequestBody::FindNode { distance: 0 };
        let mut active_request = ActiveRequest {
            node_address,
            request,
            None,
            None,
        }

        // if this is an external request, add the callback to the active request
        if let Some(callback) = callback {
            self.active_callbacks.insert(id, callback);
            active_request.callback_id = id;
        }
        self.send_rpc_request(active_request).await;
    }

    /// Sends a NODES response, given a list of found ENR's. This function splits the nodes up
    /// into multiple responses to ensure the response stays below the maximum packet size.
    async fn send_nodes_response(&mut self, node_address: NodeAddress, rpc_id: u64, distance: u64) {
        let nodes: Vec<EntryRefView<'_, NodeId, Enr>> = self
            .kbuckets
            .nodes_by_distance(distance)
            .into_iter()
            .filter(|entry| entry.node.key.preimage() != &node_address.node_id)
            .collect();
        // if there are no nodes, send an empty response
        if nodes.is_empty() {
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
            self.handler_send(HandlerRequest::Response(node_address, response))
                .await.unwrap_or_else(|| ());
        } else {
            // build the NODES response
            let mut to_send_nodes: Vec<Vec<Enr>> = Vec::new();
            let mut total_size = 0;
            let mut rpc_index = 0;
            to_send_nodes.push(Vec::new());
            for entry in nodes.into_iter() {
                let entry_size = entry.node.value.clone().encode().len();
                // Responses assume that a session is established. Thus, on top of the encoded
                // ENR's the packet should be a regular message. A regular message has a tag (32
                // bytes), and auth_tag (12 bytes) and the NODES response has an ID (8 bytes) and a total (8 bytes).
                // The encryption adds the HMAC (16 bytes) and can be at most 16 bytes larger so the total packet size can be at most 92 (given AES_GCM).
                if entry_size + total_size < MAX_PACKET_SIZE - 92 {
                    total_size += entry_size;
                    trace!("Adding ENR, Valid: {}", entry.node.value.verify());
                    trace!("Enr: {}", entry.node.value.clone());
                    to_send_nodes[rpc_index].push(entry.node.value.clone());
                } else {
                    total_size = entry_size;
                    to_send_nodes.push(vec![entry.node.value.clone()]);
                    rpc_index += 1;
                }
            }

            let responses: Vec<Response> = to_send_nodes
                .into_iter()
                .map(|nodes| Response {
                    id: rpc_id,
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
                self.handler_send(HandlerRequest::Response(node_address.clone(), response))
                    .await.unwrap_or_else(|| ());
            }
        }
    }

    /// Constructs and sends a request RPC to the session service given a `QueryInfo`.
    async fn send_rpc_query(
        &mut self,
        query_id: QueryId,
        query_info: QueryInfo,
        return_peer: &ReturnPeer<NodeId>,
    ) {
        let node_id = return_peer.key;
        trace!(
            "Sending query. Iteration: {}, NodeId: {}",
            return_peer.iteration,
            node_id
        );

        let request_body = match query_info.into_rpc_request(return_peer) {
            Ok(r) => r,
            Err(e) => {
                // dst node is local_key, report failure
                error!("Send RPC: {}", e);
                if let Some(query) = self.queries.get_mut(query_id) {
                    query.on_failure(&node_id);
                }
                return;
            }
        };

        // get the enr from the untrusted ENR list of the query
        if let Some(enr) = self.queries.get(query_id).target().untrusted_enrs.iter().find(|v| v.node_id() == node_id)  {
        let active_request = ActiveRequest {
            contact: enr.clone().into(),
            request_body,
            query_id: Some(query_id),
            None,
        }
        self.send_rpc_request(active_request).await;
        } else {
            error!("Query {} requested ENR not in it's untrusted list", query_id);
        }
    }

    /// Sends generic RPC requests. Each request gets added to known outputs, awaiting a response.
    async fn send_rpc_request(&mut self, active_request: ActiveRequest) {
        // Generate a random rpc_id which is matched per node id
        let id: u64 = rand::random(),
        let request: Request = Request {
            id: rand::random(),
            body: active_request.body.clone(),
        };
        let contact = active_request.contact.clone();
        self.active_requests.insert(id, active_request);
        debug!("Sending RPC {} to node: {}", request, contact);
        self.handler_send(HandlerRequest::Request(contact, request))
            .await.unwrap_or_else(|| ());
    }

    fn send_event(&mut self, event: Discv5Event) {
        if let Some(stream) = self.event_stream.get_mut() {
           if let TrySendError::Closed(_) = stream.try_send(event) {
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
            self.send_event(Discv5Event::Discovered(enr_ref.clone()));

            // ignore peers that don't pass the able filter
            if (self.config.table_filter)(enr_ref) {
                let key = kbucket::Key::from(enr_ref.node_id());
                if !self.config.ip_limit
                    || self
                        .kbuckets
                        .check(&key, enr_ref, { |v, o, l| ip_limiter(v, &o, l) })
                {
                    match self.kbuckets.entry(&key) {
                        kbucket::Entry::Present(mut entry, _) => {
                            if entry.value().seq() < enr_ref.seq() {
                                trace!("Enr updated: {}", enr_ref);
                                *entry.value() = enr_ref.clone();
                            }
                        }
                        kbucket::Entry::Pending(mut entry, _) => {
                            if entry.value().seq() < enr_ref.seq() {
                                trace!("Enr updated: {}", enr_ref);
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
                    .check(&key, enr, { |v, o, l| ip_limiter(v, &o, l) })
            {
                // if the node status is connected and it would exceed the ip ban, consider it
                // disconnected to be pruned.
                new_status = NodeStatus::Disconnected;
            }
        }

        match self.kbuckets.entry(&key) {
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
                                let event = ServiceEvent::NodeInserted {
                                    node_id,
                                    replaced: None,
                                };
                                self.discv5_events.push_back(event);
                            }
                            kbucket::InsertResult::Full => (),
                            kbucket::InsertResult::Pending { disconnected } => {
                                debug_assert!(!self
                                    .connected_peers
                                    .contains_key(disconnected.preimage()));
                                self.send_ping(&disconnected.into_preimage());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// The equivalent of libp2p `inject_connected()` for a udp session. We have no stream, but a
    /// session key-pair has been negotiated.
    async fn inject_session_established(&mut self, enr: Enr) {
        let node_id = enr.node_id();
        debug!("Session established with Node: {}", node_id);
        self.connection_updated(node_id.clone(), Some(enr), NodeStatus::Connected);
        // send an initial ping and start the ping interval
        self.send_ping(&node_id).await;
    }

    /// A session could not be established or an RPC request timed-out (after a few retries, if
    /// specified).
    fn rpc_failure(&mut self, id: RequestId) {
        if let Some(active_request) = self.active_rpc_requests.remove(&id)
        {
            // If this is initiated by the user, return an error on the callback. All callbacks
            // support a request error.
            if let Some(id) = active_request.callback_id {
                if let Some(callback) = self.active_callbacks.remove(id) {
                    callback.send(Err(error)).await.unwrap_or_else(|| ());
                } else {
                    crit!("Callback non-existant for id {}", id);
                }
                return;
            }

            let node_id = active_request.contact.node_id;
            match request {
                // if a failed FindNodes request, ensure we haven't partially received packets. If
                // so, process the partially found nodes
                RequestBody::FindNode { .. } => {
                    if let Some(nodes_response) = self.active_nodes_responses.remove(&node_id) {
                        if !nodes_response.received_nodes.is_empty() {
                            warn!(
                                "NODES Response failed, but was partially processed from: {}",
                                node_address
                            );
                            // if it's a query mark it as success, to process the partial
                            // collection of peers
                            self.discovered(
                                &node_id,
                                nodes_response.received_nodes,
                                query_id_option,
                            );
                        }
                    } else {
                        // there was no partially downloaded nodes inform the query of the failure
                        // if it's part of a query
                        if let Some(query_id) = query_id_option {
                            if let Some(query) = self.queries.get_mut(query_id) {
                                query.on_failure(&node_id);
                            }
                        } else {
                            debug!("Failed RPC request: {}: {} ", request, node_address);
                        }
                    }
                }
                // for all other requests, if any are queries, mark them as failures.
                _ => {
                    if let Some(query_id) = query_id_option {
                        if let Some(query) = self.queries.get_mut(query_id) {
                            debug!(
                                "Failed query request: {} for query: {} and {} ",
                                request, *query_id, node_address
                            );
                            query.on_failure(&node_id);
                        }
                    } else {
                        debug!("Failed RPC request: {:?} for node: {} ", request, node_id);
                    }
                }
            }

            self.connection_updated(node_id, None, NodeStatus::Disconnected);
            if self.connected_peers.remove(&node_id).is_some() {
                // report the node as being disconnected
                debug!("Session dropped with {}", node_address);
            }
        }
    }

    /// A future that maintains the routing table and inserts nodes when required. This returns the
    /// `Discv5Event::NodeInserted` variant if a new node has been inserted into the routing table.
    async fn bucket_maintenance_poll(kbuckets: &mut KBucketsTable<NodeId, Enr>) -> Discv5Event {
        future::poll_fn(move |_cx| {
            // Drain applied pending entries from the routing table.
            if let Some(entry) = kbuckets.take_applied_pending() {
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
            QueryPoolState::Finished(query) => Poll::Ready(QueryEvent::Finished(query)),
            QueryPoolState::Waiting(Some((query, return_peer))) => Poll::Ready(
                QueryEvent::Waiting(query.id(), query.target().clone(), return_peer),
            ),
            QueryPoolState::Timeout(query) => {
                warn!("Query id: {:?} timed out", query.id());
                Poll::Ready(QueryEvent::TimedOut(query))
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
    Waiting(QueryId, QueryInfo, ReturnPeer<NodeId>),
    /// The query has timed out, possible returning peers.
    TimedOut(crate::query_pool::Query<QueryInfo, NodeId, Enr>),
    /// The query has completed successfully.
    Finished(crate::query_pool::Query<QueryInfo, NodeId, Enr>),
}
