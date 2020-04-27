//! The protocol behaviour of Discovery v5. See `lib.rs` for further details.
//!
//! Note: Discovered ENR's are not automatically added to the routing table. Only established
//! sessions get added, ensuring only valid ENRs are added. Manual additions can be made using the
//! `add_enr()` function.
//!
//! Response to queries return `PeerId`. Only the trusted (a session has been established with)
//! `PeerId`'s are returned, as ENR's for these `PeerId`'s are stored in the routing table and as
//! such should have an address to connect to. Untrusted `PeerId`'s can be obtained from the
//! `Discv5::Discovered` event, which is fired as peers get discovered.
//!
//! Note that although the ENR crate does support Ed25519 keys, these are currently not
//! supported as the ECDH procedure isn't specified in the specification. Therefore, only
//! secp256k1 keys are supported currently.

use self::ip_vote::IpVote;
use self::query_info::{QueryInfo, QueryType};
use crate::error::Discv5Error;
use crate::kbucket::{self, EntryRefView, KBucketsTable, NodeStatus};
use crate::query_pool::{
    FindNodeQueryConfig, PredicateQueryConfig, QueryId, QueryPool, QueryPoolState, ReturnPeer,
};
use crate::rpc;
use crate::service::MAX_PACKET_SIZE;
use crate::session_service::{SessionEvent, SessionService};
use crate::Discv5Config;
use enr::{CombinedKey, Enr, EnrError, EnrKey, NodeId};
use fnv::FnvHashMap;
use futures::prelude::*;
use libp2p_core::ConnectedPoint;
use libp2p_core::{
    identity::Keypair,
    multiaddr::{Multiaddr, Protocol},
    PeerId,
};
use libp2p_swarm::{
    protocols_handler::{DummyProtocolsHandler, ProtocolsHandler},
    NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use log::{debug, error, info, trace, warn};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::{marker::PhantomData, time::Duration};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_timer::Interval;

mod ip_vote;
mod query_info;
mod test;

type RpcId = u64;

#[derive(Clone, PartialEq, Eq, Hash)]
struct RpcRequest(RpcId, NodeId);

pub struct Discv5<TSubstream> {
    /// Events yielded by this behaviour.
    events: SmallVec<[Discv5Event; 32]>,

    /// Configuration parameters for the Discv5 service
    config: Discv5Config,

    /// Abstract the NodeId from libp2p. For all known ENR's we keep a mapping of PeerId to NodeId.
    known_peer_ids: HashMap<PeerId, NodeId>,

    /// Storage of the ENR record for each node.
    kbuckets: KBucketsTable<NodeId, Enr<CombinedKey>>,

    /// All the iterative queries we are currently performing.
    queries: QueryPool<QueryInfo, NodeId, Enr<CombinedKey>>,

    /// RPC requests that have been sent and are awaiting a response. Some requests are linked to a
    /// query.
    active_rpc_requests: FnvHashMap<RpcRequest, (Option<QueryId>, rpc::Request)>,

    /// Keeps track of the number of responses received from a NODES response.
    active_nodes_responses: HashMap<NodeId, NodesResponse>,

    /// A map of votes nodes have made about our external IP address. We accept the majority.
    ip_votes: Option<IpVote>,

    /// List of peers we have established sessions with and an interval for when to send a PING.
    connected_peers: HashMap<NodeId, Interval>,

    /// Main discv5 UDP service that establishes sessions with peers.
    service: SessionService,

    /// Marker to pin the generics.
    marker: PhantomData<TSubstream>,
}

/// For multiple responses to a FindNodes request, this struct keeps track of the request count
/// and the nodes that have been received.
struct NodesResponse {
    /// The response count.
    count: usize,
    /// The filtered nodes that have been received.
    received_nodes: Vec<Enr<CombinedKey>>,
}

impl Default for NodesResponse {
    fn default() -> Self {
        NodesResponse {
            count: 1,
            received_nodes: Vec::new(),
        }
    }
}

impl<TSubstream> Discv5<TSubstream> {
    /// Builds the `Discv5` main struct.
    ///
    /// `local_enr` is the `ENR` representing the local node. This contains node identifying information, such
    /// as IP addresses and ports which we wish to broadcast to other nodes via this discovery
    /// mechanism. The `listen_socket` determines which UDP socket address the behaviour will listen on.
    pub fn new(
        local_enr: Enr<CombinedKey>,
        keypair: Keypair,
        config: Discv5Config,
        listen_socket: SocketAddr,
    ) -> Result<Self, Discv5Error> {
        let node_id = local_enr.node_id().clone();
        // Note: Currently only the secp256k1 keypair is supported. Perform the check here
        match keypair {
            Keypair::Secp256k1(_) => {} // this key type is fine
            _ => {
                return Err(Discv5Error::KeyTypeNotSupported(
                    "This libp2p key type is not supported",
                ));
            }
        }
        let enr_key: CombinedKey = keypair.try_into().map_err(|_| {
            Discv5Error::KeyTypeNotSupported("This libp2p key type is not supported")
        })?;

        // ensure the keypair matches the one that signed the enr.
        if local_enr.public_key() != enr_key.public() {
            return Err(Discv5Error::Custom(
                "Discv5: Provided keypair does not match the provided ENR keypair",
            ));
        }

        // process behaviour-level configuration parameters
        let ip_votes = if config.enr_update {
            Some(IpVote::new(config.enr_peer_update_min))
        } else {
            None
        };

        // build the sesison service
        let service = SessionService::new(local_enr, enr_key, listen_socket, config.clone())?;

        let query_timeout = config.query_timeout;
        Ok(Discv5 {
            events: SmallVec::new(),
            config,
            known_peer_ids: HashMap::new(),
            kbuckets: KBucketsTable::new(node_id.into(), Duration::from_secs(60)),
            queries: QueryPool::new(query_timeout),
            active_rpc_requests: Default::default(),
            active_nodes_responses: HashMap::new(),
            ip_votes,
            connected_peers: Default::default(),
            service,
            marker: PhantomData,
        })
    }

    /// Adds a known ENR of a peer participating in Discv5 to the
    /// routing table.
    ///
    /// This allows pre-populating the Kademlia routing table with known
    /// addresses, so that they can be used immediately in following DHT
    /// operations involving one of these peers, without having to dial
    /// them upfront.
    pub fn add_enr(&mut self, enr: Enr<CombinedKey>) -> Result<(), &'static str> {
        // only add ENR's that have a valid udp socket.
        if enr.udp_socket().is_none() {
            warn!("ENR attempted to be added without a UDP socket has been ignored");
            return Err("Enr has no UDP socket to connect to");
        }

        // add to the known_peer_ids mapping
        self.known_peer_ids
            .insert(enr.peer_id(), enr.node_id().clone());
        let key = kbucket::Key::from(enr.node_id().clone());

        // should the ENR be inserted or updated to a value that would exceed the IP limit ban
        let ip_limit_ban = self.config.ip_limit
            && !self
                .kbuckets
                .check(&key, &enr, { |v, o, l| ip_limiter(v, &o, l) });

        match self.kbuckets.entry(&key) {
            kbucket::Entry::Present(mut entry, _) => {
                // still update an ENR, regardless of the IP limit ban
                *entry.value() = enr;
            }
            kbucket::Entry::Pending(mut entry, _) => {
                *entry.value() = enr;
            }
            kbucket::Entry::Absent(entry) => {
                if !ip_limit_ban {
                    match entry.insert(enr.clone(), NodeStatus::Disconnected) {
                        kbucket::InsertResult::Inserted => {
                            let event = Discv5Event::EnrAdded {
                                enr,
                                replaced: None,
                            };
                            self.events.push(event);
                        }
                        kbucket::InsertResult::Full => (),
                        kbucket::InsertResult::Pending { disconnected } => {
                            // Try and establish a connection
                            self.send_ping(&disconnected.into_preimage());
                        }
                    }
                }
            }
            kbucket::Entry::SelfEntry => {}
        };
        Ok(())
    }

    /// Returns the number of connected peers the behaviour knows about.
    pub fn connected_peers(&self) -> usize {
        self.connected_peers.len()
    }

    /// Returns the local ENR of the node.
    pub fn local_enr(&self) -> &Enr<CombinedKey> {
        &self.service.enr()
    }

    /// Allows the application layer to update the local ENR's UDP socket. The second parameter
    /// determines whether the port is a TCP port. If this parameter is false, this is
    /// interpreted as a UDP `SocketAddr`.
    pub fn update_local_enr_socket(&mut self, socket_addr: SocketAddr, is_tcp: bool) -> bool {
        if is_tcp {
            if self.local_enr().tcp_socket() == Some(socket_addr) {
                // nothing to do, not updated
                return false;
            }
        } else if self.local_enr().udp_socket() == Some(socket_addr) {
            // nothing to do, not updated
            return false;
        }
        // a new socket addr has been supplied
        if self
            .service
            .update_local_enr_socket(socket_addr, is_tcp)
            .is_ok()
        {
            // notify peers of the update
            self.ping_connected_peers();
            true
        } else {
            false
        }
    }

    /// Allows application layer to insert an arbitrary field into the local ENR.
    pub fn enr_insert(&mut self, key: &str, value: Vec<u8>) -> Result<Option<Vec<u8>>, EnrError> {
        let result = self.service.enr_insert(key, value);

        if result.is_ok() {
            self.ping_connected_peers();
        }
        result
    }

    /// Returns an iterator over all ENR node IDs of nodes currently contained in a bucket
    /// of the Kademlia routing table.
    pub fn kbuckets_entries(&mut self) -> impl Iterator<Item = &NodeId> {
        self.kbuckets.iter().map(|entry| entry.node.key.preimage())
    }

    /// Returns an iterator over all the ENR's of nodes currently contained in a bucket of
    /// the Kademlia routing table.
    pub fn enr_entries(&mut self) -> impl Iterator<Item = &Enr<CombinedKey>> {
        self.kbuckets.iter().map(|entry| entry.node.value)
    }

    /// Starts an iterative `FIND_NODE` request.
    ///
    /// This will eventually produce an event containing the nodes of the DHT closest to the
    /// requested `PeerId`.
    pub fn find_node(&mut self, target_node: NodeId) {
        self.start_findnode_query(target_node);
    }

    /// Starts a `FIND_NODE` request.
    ///
    /// This will eventually produce an event containing <= `num` nodes which satisfy the
    /// `predicate` with passed `value`.
    pub fn find_enr_predicate<F>(&mut self, node_id: NodeId, predicate: F, num_nodes: usize)
    where
        F: Fn(&Enr<CombinedKey>) -> bool + Send + Clone + 'static,
    {
        self.start_predicate_query(node_id, predicate, num_nodes);
    }

    /// If an ENR is known for a PeerId it is returned.
    pub fn enr_of_peer(&mut self, peer_id: &PeerId) -> Option<Enr<CombinedKey>> {
        let node_id = self.known_peer_ids.get(peer_id)?.clone();
        self.find_enr(&node_id)
    }

    // private functions //

    /// Processes an RPC request from a peer. Requests respond to the received socket address,
    /// rather than the IP of the known ENR.
    fn handle_rpc_request(
        &mut self,
        src: SocketAddr,
        node_id: NodeId,
        rpc_id: u64,
        req: rpc::Request,
    ) {
        match req {
            rpc::Request::FindNode { distance } => {
                // if the distance is 0 send our local ENR
                if distance == 0 {
                    let response = rpc::ProtocolMessage {
                        id: rpc_id,
                        body: rpc::RpcType::Response(rpc::Response::Nodes {
                            total: 1,
                            nodes: vec![self.local_enr().clone()],
                        }),
                    };
                    debug!("Sending our ENR to node: {}", node_id);
                    let _ = self
                        .service
                        .send_response(src, &node_id, response)
                        .map_err(|e| warn!("Failed to send a FINDNODES response. Error: {:?}", e));
                } else {
                    self.send_nodes_response(src, node_id, rpc_id, distance);
                }
            }
            rpc::Request::Ping { enr_seq } => {
                // check if we need to update the known ENR
                match self.kbuckets.entry(&node_id.clone().into()) {
                    kbucket::Entry::Present(ref mut entry, _) => {
                        if entry.value().seq() < enr_seq {
                            self.request_enr(&node_id, src);
                        }
                    }
                    kbucket::Entry::Pending(ref mut entry, _) => {
                        if entry.value().seq() < enr_seq {
                            self.request_enr(&node_id, src);
                        }
                    }
                    // don't know of the ENR, request the update
                    _ => self.request_enr(&node_id, src),
                }

                // build the PONG response
                let response = rpc::ProtocolMessage {
                    id: rpc_id,
                    body: rpc::RpcType::Response(rpc::Response::Ping {
                        enr_seq: self.local_enr().seq(),
                        ip: src.ip(),
                        port: src.port(),
                    }),
                };
                debug!("Sending PONG response to node: {}", node_id);
                let _ = self
                    .service
                    .send_response(src, &node_id, response)
                    .map_err(|e| warn!("Failed to send rpc request. Error: {:?}", e));
            }
            _ => {} //TODO: Implement all RPC methods
        }
    }

    /// Processes an RPC response from a peer.
    fn handle_rpc_response(&mut self, node_id: NodeId, rpc_id: u64, res: rpc::Response) {
        // verify we know of the rpc_id
        let req = RpcRequest(rpc_id, node_id.clone());
        if let Some((query_id, request)) = self.active_rpc_requests.remove(&req) {
            if !res.match_request(&request) {
                warn!(
                    "Node gave an incorrect response type. Ignoring response from node: {}",
                    node_id
                );
                return;
            }
            match res {
                rpc::Response::Nodes { total, mut nodes } => {
                    // Currently a maximum of 16 peers can be returned. Datagrams have a max
                    // size of 1280 and ENR's have a max size of 300 bytes. There should be no
                    // more than 5 responses, to return 16 peers.
                    if total > 5 {
                        warn!("NodesResponse has a total larger than 5, nodes will be truncated");
                    }

                    // filter out any nodes that are not of the correct distance
                    // TODO: If a swarm peer reputation is built - downvote the peer if all
                    // peers do not have the correct distance.
                    let peer_key: kbucket::Key<NodeId> = node_id.clone().into();
                    let distance_requested = match request {
                        rpc::Request::FindNode { distance } => distance,
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
                            .remove(&node_id)
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
                            self.active_rpc_requests.insert(req, (query_id, request));
                            self.active_nodes_responses
                                .insert(node_id, current_response);
                            return;
                        }

                        // have received all the Nodes responses we are willing to accept
                        // ignore duplicates here as they will be handled when adding
                        // to the DHT
                        current_response.received_nodes.append(&mut nodes);
                        nodes = current_response.received_nodes;
                    }

                    debug!(
                        "Received a nodes response of len: {}, total: {}, from node_id: {}",
                        nodes.len(),
                        total,
                        node_id
                    );
                    // note: If a peer sends an initial NODES response with a total > 1 then
                    // in a later response sends a response with a total of 1, all previous nodes
                    // will be ignored.
                    // ensure any mapping is removed in this rare case
                    self.active_nodes_responses.remove(&node_id);

                    self.discovered(&node_id, nodes, query_id);
                }
                rpc::Response::Ping { enr_seq, ip, port } => {
                    let socket = SocketAddr::new(ip, port);
                    // perform ENR majority-based update if required.
                    let local_socket = self.local_enr().udp_socket();
                    if let Some(ref mut ip_votes) = self.ip_votes {
                        ip_votes.insert(node_id.clone(), socket.clone());
                        let majority_socket = ip_votes.majority();
                        if majority_socket.is_some() && majority_socket != local_socket {
                            let majority_socket = majority_socket.expect("is some");
                            info!("Local UDP socket updated to: {}", majority_socket);
                            self.events
                                .push(Discv5Event::SocketUpdated(majority_socket));
                            if self
                                .service
                                .update_local_enr_socket(majority_socket, false)
                                .is_ok()
                            {
                                // alert known peers to our updated enr
                                self.ping_connected_peers();
                            }
                        }
                    }

                    // check if we need to request a new ENR
                    if let Some(enr) = self.find_enr(&node_id) {
                        if enr.seq() < enr_seq {
                            // request an ENR update
                            debug!("Requesting an ENR update from node: {}", node_id);
                            let req = rpc::Request::FindNode { distance: 0 };
                            self.send_rpc_request(&node_id, req, None);
                        }
                        self.connection_updated(node_id.clone(), Some(enr), NodeStatus::Connected)
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
    fn send_ping(&mut self, node_id: &NodeId) {
        let req = rpc::Request::Ping {
            enr_seq: self.local_enr().seq(),
        };
        self.send_rpc_request(&node_id, req, None);
    }

    fn ping_connected_peers(&mut self) {
        // maintain the ping interval
        let connected_nodes: Vec<NodeId> = self.connected_peers.keys().cloned().collect();
        for node_id in connected_nodes {
            self.send_ping(&node_id);
        }
    }

    /// Request an external node's ENR.
    // This logic doesn't fit into a standard request - We likely don't know the ENR,
    // and would like to send this as a response, with request logic built in.
    fn request_enr(&mut self, node_id: &NodeId, src: SocketAddr) {
        // Generate a random rpc_id which is matched per node id
        let id: u64 = rand::random();
        let req = rpc::Request::FindNode { distance: 0 };
        let message = rpc::ProtocolMessage {
            id,
            body: rpc::RpcType::Request(req.clone()),
        };
        debug!("Sending ENR request to node: {}", node_id);

        match self.service.send_request_unknown_enr(src, node_id, message) {
            Ok(_) => {
                let rpc_request = RpcRequest(id, node_id.clone());
                self.active_rpc_requests.insert(rpc_request, (None, req));
            }
            _ => warn!("Requesting ENR failed. Node: {}", node_id),
        }
    }

    /// Sends a NODES response, given a list of found ENR's. This function splits the nodes up
    /// into multiple responses to ensure the response stays below the maximum packet size.
    fn send_nodes_response(
        &mut self,
        dst: SocketAddr, // overwrites the ENR IP - we resend to the IP we received the request from
        dst_id: NodeId,
        rpc_id: u64,
        distance: u64,
    ) {
        let nodes: Vec<EntryRefView<NodeId, Enr<CombinedKey>>> = self
            .kbuckets
            .nodes_by_distance(distance)
            .into_iter()
            .filter(|entry| entry.node.key.preimage() != &dst_id)
            .collect();
        // if there are no nodes, send an empty response
        if nodes.is_empty() {
            let response = rpc::ProtocolMessage {
                id: rpc_id,
                body: rpc::RpcType::Response(rpc::Response::Nodes {
                    total: 1u64,
                    nodes: Vec::new(),
                }),
            };
            trace!("Sending empty FINDNODES response to: {}", dst_id);
            let _ = self
                .service
                .send_response(dst, &dst_id, response)
                .map_err(|e| warn!("Failed to send a FINDNODES response. Error: {:?}", e));
        } else {
            // build the NODES response
            let mut to_send_nodes: Vec<Vec<Enr<CombinedKey>>> = Vec::new();
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

            let responses: Vec<rpc::ProtocolMessage> = to_send_nodes
                .into_iter()
                .map(|nodes| rpc::ProtocolMessage {
                    id: rpc_id,
                    body: rpc::RpcType::Response(rpc::Response::Nodes {
                        total: (rpc_index + 1) as u64,
                        nodes,
                    }),
                })
                .collect();

            for response in responses {
                trace!(
                    "Sending FINDNODES response to: {}. Response: {:?}",
                    dst_id,
                    response.clone().encode()
                );
                let _ = self
                    .service
                    .send_response(dst, &dst_id, response)
                    .map_err(|e| warn!("Failed to send a FINDNODES response. Error: {:?}", e));
            }
        }
    }

    /// Constructs and sends a request RPC to the session service given a `QueryInfo`.
    fn send_rpc_query(
        &mut self,
        query_id: QueryId,
        query_info: QueryInfo,
        return_peer: &ReturnPeer<NodeId>,
    ) {
        let node_id = return_peer.node_id.clone();
        trace!(
            "Sending query. Iteration: {}, NodeId: {}",
            return_peer.iteration,
            node_id
        );

        let req = match query_info.into_rpc_request(return_peer) {
            Ok(r) => r,
            Err(e) => {
                //dst node is local_key, report failure
                error!("Send RPC: {}", e);
                if let Some(query) = self.queries.get_mut(&query_id) {
                    query.on_failure(&node_id);
                }
                return;
            }
        };

        self.send_rpc_request(&node_id, req, Some(query_id));
    }

    /// Sends generic RPC requests. Each request gets added to known outputs, awaiting a response.
    fn send_rpc_request(&mut self, node_id: &NodeId, req: rpc::Request, query_id: Option<QueryId>) {
        // find the destination ENR
        if let Some(dst_enr) = self.find_enr(&node_id) {
            // Generate a random rpc_id which is matched per node id
            let id: u64 = rand::random();

            debug!(
                "Sending RPC Request: {:?} to node: {}",
                req,
                dst_enr.node_id()
            );
            match self.service.send_request(
                &dst_enr,
                rpc::ProtocolMessage {
                    id,
                    body: rpc::RpcType::Request(req.clone()),
                },
            ) {
                Ok(_) => {
                    let rpc_request = RpcRequest(id, node_id.clone());
                    self.active_rpc_requests
                        .insert(rpc_request, (query_id, req));
                }
                Err(_) => {
                    warn!("Sending request to node: {} failed", &node_id);
                    if let Some(query_id) = query_id {
                        if let Some(query) = self.queries.get_mut(&query_id) {
                            query.on_failure(&node_id);
                        }
                    }
                }
            }
        } else {
            warn!(
                "Request not sent. Failed to find ENR for Node: {:?}",
                node_id
            );
        }
    }

    /// Returns an ENR if one is known for the given NodeId.
    fn find_enr(&mut self, node_id: &NodeId) -> Option<Enr<CombinedKey>> {
        // check if we know this node id in our routing table
        let key = kbucket::Key::from(node_id.clone());
        if let kbucket::Entry::Present(mut entry, _) = self.kbuckets.entry(&key) {
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

    /// Internal function that starts a query.
    fn start_findnode_query(&mut self, target_node: NodeId) {
        let target = QueryInfo {
            query_type: QueryType::FindNode(target_node),
            untrusted_enrs: Default::default(),
        };

        // How many times to call the rpc per node.
        // FINDNODE requires multiple iterations as it requests a specific distance.
        let query_iterations = target.iterations();

        let target_key: kbucket::Key<QueryInfo> = target.clone().into();

        let known_closest_peers = self.kbuckets.closest_keys(&target_key);
        let query_config = FindNodeQueryConfig::new_from_config(&self.config);
        self.queries.add_findnode_query(
            query_config,
            target,
            known_closest_peers,
            query_iterations,
        );
    }

    /// Internal function that starts a query.
    fn start_predicate_query<F>(&mut self, target_node: NodeId, predicate: F, num_nodes: usize)
    where
        F: Fn(&Enr<CombinedKey>) -> bool + Send + Clone + 'static,
    {
        let target = QueryInfo {
            query_type: QueryType::FindNode(target_node),
            untrusted_enrs: Default::default(),
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
        );
    }

    /// Processes discovered peers from a query.
    fn discovered(
        &mut self,
        source: &NodeId,
        peers: Vec<Enr<CombinedKey>>,
        query_id: Option<QueryId>,
    ) {
        let local_id = self.local_enr().node_id().clone();
        let others_iter = peers.into_iter().filter(|p| p.node_id() != local_id);

        for peer in others_iter.clone() {
            // If any of the discovered nodes are in the routing table, and there contains an older ENR, update it.
            self.events.push(Discv5Event::Discovered(peer.clone()));

            let key = kbucket::Key::from(peer.node_id());
            if !self.config.ip_limit
                || self
                    .kbuckets
                    .check(&key, &peer, { |v, o, l| ip_limiter(v, &o, l) })
            {
                match self.kbuckets.entry(&key) {
                    kbucket::Entry::Present(mut entry, _) => {
                        if entry.value().seq() < peer.seq() {
                            trace!("Enr updated: {}", peer);
                            *entry.value() = peer.clone();
                            self.service.update_enr(peer);
                        }
                    }
                    kbucket::Entry::Pending(mut entry, _) => {
                        if entry.value().seq() < peer.seq() {
                            trace!("Enr updated: {}", peer);
                            *entry.value() = peer.clone();
                            self.service.update_enr(peer);
                        }
                    }
                    kbucket::Entry::Absent(_entry) => {
                        // the service may have an untrusted session
                        // update the service, which will inform this protocol if a session is
                        // established or not.
                        self.service.update_enr(peer);
                    }
                    _ => {}
                }
            }
        }

        // if this is part of a query, update the query
        if let Some(query_id) = query_id {
            if let Some(query) = self.queries.get_mut(&query_id) {
                let mut peer_count = 0;
                for peer in others_iter.clone() {
                    if query
                        .target_mut()
                        .untrusted_enrs
                        .iter()
                        .position(|e| e.node_id() == peer.node_id())
                        .is_none()
                    {
                        query.target_mut().untrusted_enrs.push(peer);
                    }
                    peer_count += 1;
                }
                debug!("{} peers found for query id {:?}", peer_count, query_id);
                query.on_success(source, &others_iter.collect())
            }
        }
    }

    /// Update the connection status of a node in the routing table.
    fn connection_updated(
        &mut self,
        node_id: NodeId,
        enr: Option<Enr<CombinedKey>>,
        mut new_status: NodeStatus,
    ) {
        let key = kbucket::Key::from(node_id.clone());

        // add the known PeerId
        if let Some(enr) = enr.clone() {
            self.known_peer_ids
                .insert(enr.peer_id().clone(), enr.node_id());

            // should the ENR be inserted or updated to a value that would exceed the IP limit ban
            if self.config.ip_limit
                && !self
                    .kbuckets
                    .check(&key, &enr, { |v, o, l| ip_limiter(v, &o, l) })
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
                                let event = Discv5Event::NodeInserted {
                                    node_id: node_id.clone(),
                                    replaced: None,
                                };
                                self.events.push(event);
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
    fn inject_session_established(&mut self, enr: Enr<CombinedKey>) {
        let node_id = enr.node_id().clone();
        debug!("Session established with Node: {}", node_id);
        self.known_peer_ids.insert(enr.peer_id(), node_id.clone());
        self.connection_updated(node_id.clone(), Some(enr), NodeStatus::Connected);
        // send an initial ping and start the ping interval
        self.send_ping(&node_id);
        let interval = Interval::new_interval(self.config.ping_interval);
        self.connected_peers.insert(node_id, interval);
    }

    /// A session could not be established or an RPC request timed-out (after a few retries).
    fn rpc_failure(&mut self, node_id: NodeId, failed_rpc_id: RpcId) {
        let req = RpcRequest(failed_rpc_id, node_id.clone());

        if let Some((query_id_option, request)) = self.active_rpc_requests.remove(&req) {
            match request {
                // if a failed FindNodes request, ensure we haven't partially received packets. If
                // so, process the partially found nodes
                rpc::Request::FindNode { .. } => {
                    if let Some(nodes_response) = self.active_nodes_responses.remove(&node_id) {
                        if !nodes_response.received_nodes.is_empty() {
                            warn!(
                                "NODES Response failed, but was partially processed from Node: {}",
                                node_id
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
                            if let Some(query) = self.queries.get_mut(&query_id) {
                                query.on_failure(&node_id);
                            }
                        } else {
                            debug!("Failed RPC request: {:?} for node: {} ", request, node_id);
                        }
                    }
                }
                // for all other requests, if any are queries, mark them as failures.
                _ => {
                    if let Some(query_id) = query_id_option {
                        if let Some(query) = self.queries.get_mut(&query_id) {
                            debug!(
                                "Failed query request: {:?} for query: {:?} and node: {} ",
                                request, query_id, node_id
                            );
                            query.on_failure(&node_id);
                        }
                    } else {
                        debug!("Failed RPC request: {:?} for node: {} ", request, node_id);
                    }
                }
            }
        }

        // report the node as being disconnected
        debug!("Session dropped with Node: {}", node_id);
        self.connection_updated(node_id.clone(), None, NodeStatus::Disconnected);
        self.connected_peers.remove(&node_id);
    }
}

impl<TSubstream> NetworkBehaviour for Discv5<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type ProtocolsHandler = DummyProtocolsHandler<TSubstream>;
    type OutEvent = Discv5Event;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        DummyProtocolsHandler::default()
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        // Addresses are ordered by decreasing likelyhood of connectivity, so start with
        // the addresses of that peer in the k-buckets.

        if let Some(node_id) = self.known_peer_ids.get(peer_id) {
            let key = kbucket::Key::from(node_id.clone());
            let mut out_list =
                if let kbucket::Entry::Present(mut entry, _) = self.kbuckets.entry(&key) {
                    entry.value().multiaddr().to_vec()
                } else {
                    Vec::new()
                };

            // ENR's may have multiple Multiaddrs. The multi-addr associated with the UDP
            // port is removed, which is assumed to be associated with the discv5 protocol (and
            // therefore irrelevant for other libp2p components).
            out_list.retain(|addr| {
                addr.iter()
                    .find(|v| match v {
                        Protocol::Udp(_) => true,
                        _ => false,
                    })
                    .is_none()
            });

            out_list
        } else {
            // PeerId is not known
            Vec::new()
        }
    }

    // ignore libp2p connections/streams
    fn inject_connected(&mut self, _: PeerId, _: ConnectedPoint) {}

    // ignore libp2p connections/streams
    fn inject_disconnected(&mut self, _: &PeerId, _: ConnectedPoint) {}

    // no libp2p discv5 events - event originate from the session_service.
    fn inject_node_event(
        &mut self,
        _: PeerId,
        _ev: <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        void::unreachable(_ev)
    }

    fn poll(
        &mut self,
        _params: &mut impl PollParameters,
    ) -> Async<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        loop {
            // Process events from the session service
            while let Async::Ready(event) = self.service.poll() {
                match event {
                    SessionEvent::Established(enr) => {
                        self.inject_session_established(enr);
                    }
                    SessionEvent::Message {
                        src_id,
                        src,
                        message,
                    } => match message.body {
                        rpc::RpcType::Request(req) => {
                            self.handle_rpc_request(src, src_id, message.id, req);
                        }
                        rpc::RpcType::Response(res) => {
                            self.handle_rpc_response(src_id, message.id, res)
                        }
                    },
                    SessionEvent::WhoAreYouRequest {
                        src,
                        src_id,
                        auth_tag,
                    } => {
                        // check what our latest known ENR is for this node.
                        if let Some(known_enr) = self.find_enr(&src_id) {
                            self.service.send_whoareyou(
                                src,
                                &src_id,
                                known_enr.seq(),
                                Some(known_enr.clone()),
                                auth_tag,
                            );
                        } else {
                            // do not know of this peer
                            debug!("NodeId unknown, requesting ENR. NodeId: {}", src_id);
                            self.service.send_whoareyou(src, &src_id, 0, None, auth_tag)
                        }
                    }
                    SessionEvent::RequestFailed(node_id, rpc_id) => {
                        self.rpc_failure(node_id, rpc_id);
                    }
                }
            }

            // Drain queued events
            if !self.events.is_empty() {
                return Async::Ready(NetworkBehaviourAction::GenerateEvent(self.events.remove(0)));
            }
            self.events.shrink_to_fit();

            // Drain applied pending entries from the routing table.
            if let Some(entry) = self.kbuckets.take_applied_pending() {
                let event = Discv5Event::NodeInserted {
                    node_id: entry.inserted.into_preimage(),
                    replaced: entry.evicted.map(|n| n.key.into_preimage()),
                };
                return Async::Ready(NetworkBehaviourAction::GenerateEvent(event));
            }

            // Handle active queries

            // If iterating finds a query that is finished, stores it here and stops looping.
            let mut finished_query = None;
            // If a query is waiting for an rpc to send, store it here and stop looping.
            let mut waiting_query = None;
            loop {
                match self.queries.poll() {
                    QueryPoolState::Finished(query) => {
                        finished_query = Some(query);
                        break;
                    }
                    QueryPoolState::Waiting(Some((query, return_peer))) => {
                        waiting_query = Some((query.id(), query.target().clone(), return_peer));
                        break;
                    }
                    QueryPoolState::Timeout(query) => {
                        warn!("Query id: {:?} timed out", query.id());
                        finished_query = Some(query);
                        break;
                    }
                    QueryPoolState::Waiting(None) | QueryPoolState::Idle => break,
                };
            }

            if let Some((query_id, target, return_peer)) = waiting_query {
                self.send_rpc_query(query_id, target, &return_peer);
            } else if let Some(finished_query) = finished_query {
                let result = finished_query.into_result();

                match result.target.query_type {
                    QueryType::FindNode(node_id) => {
                        let event = Discv5Event::FindNodeResult {
                            key: node_id,
                            closer_peers: result
                                .closest_peers
                                .filter_map(|p| self.find_enr(&p).and_then(|p| Some(p.peer_id())))
                                .collect(),
                        };
                        return Async::Ready(NetworkBehaviourAction::GenerateEvent(event));
                    }
                }
            } else {
                // check for ping intervals
                let mut to_send_ping = Vec::new();
                for (node_id, interval) in self.connected_peers.iter_mut() {
                    while let Ok(Async::Ready(_)) = interval.poll() {
                        to_send_ping.push(node_id.clone());
                    }
                }
                to_send_ping.dedup();
                for id in to_send_ping.into_iter() {
                    debug!("Sending PING to: {}", id);
                    self.send_ping(&id);
                }

                return Async::NotReady;
            }
        }
    }
}

/// Takes an `enr` to insert and a list of other `enrs` to compare against.
/// Returns `true` if `enr` can be inserted and `false` otherwise.
/// `enr` can be inserted if the count of enrs in `others` in the same /24 subnet as `enr`
/// is less than `limit`.
fn ip_limiter(enr: &Enr<CombinedKey>, others: &Vec<&Enr<CombinedKey>>, limit: usize) -> bool {
    let mut allowed = true;
    if let Some(ip) = enr.ip() {
        let count = others.iter().flat_map(|e| e.ip()).fold(0, |acc, x| {
            if x.octets()[0..3] == ip.octets()[0..3] {
                acc + 1
            } else {
                acc
            }
        });
        if count >= limit {
            allowed = false;
        }
    };
    allowed
}

/// Event that can be produced by the `Discv5` behaviour.
#[derive(Debug)]
pub enum Discv5Event {
    /// A node has been discovered from a FINDNODES request.
    ///
    /// The ENR of the node is returned. Various properties can be derived from the ENR.
    /// - `PeerId`: enr.peer_id()
    /// - `Multiaddr`: enr.multiaddr()
    /// - `NodeId`: enr.node_id()
    Discovered(Enr<CombinedKey>),
    /// A new ENR was added to the routing table.
    EnrAdded {
        enr: Enr<CombinedKey>,
        replaced: Option<Enr<CombinedKey>>,
    },
    /// A new node has been added to the routing table.
    NodeInserted {
        node_id: NodeId,
        replaced: Option<NodeId>,
    },
    /// Our local ENR IP address has been updated.
    SocketUpdated(SocketAddr),
    /// Result of a `FIND_NODE` iterative query.
    FindNodeResult {
        /// The key that we looked for in the query.
        key: NodeId,
        /// List of peers ordered from closest to furthest away.
        closer_peers: Vec<PeerId>,
    },
}
