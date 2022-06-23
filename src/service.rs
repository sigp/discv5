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
    advertisement::{
        ticket::{ActiveRegtopicRequests, TicketPools, Tickets},
        topic::TopicHash,
        Ads,
    },
    error::{RequestError, ResponseError},
    handler::{Handler, HandlerIn, HandlerOut},
    kbucket::{
        self, ConnectionDirection, ConnectionState, FailureReason, InsertResult, KBucketsTable,
        NodeStatus, UpdateResult,
    },
    metrics::METRICS,
    node_info::{NodeAddress, NodeContact, NonContactable},
    packet::MAX_PACKET_SIZE,
    query_pool::{
        FindNodeQueryConfig, PredicateQueryConfig, QueryId, QueryPool, QueryPoolState, TargetKey,
    },
    rpc, Discv5Config, Discv5Event, Enr,
};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    Aes128Gcm,
};
use delay_map::HashSetDelay;
use enr::{CombinedKey, NodeId};
use fnv::FnvHashMap;
use futures::{future::select_all, prelude::*};
use more_asserts::debug_unreachable;
use parking_lot::RwLock;
use rpc::*;
use std::{
    collections::{hash_map::Entry, HashMap},
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::{atomic::Ordering, Arc},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace, warn};

mod ip_vote;
mod query_info;
mod test;

/// The number of distances (buckets) we simultaneously request from each peer.
/// NOTE: This must not be larger than 127.
pub(crate) const DISTANCES_TO_REQUEST_PER_PEER: usize = 3;

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

/// The max wait time accpeted for tickets.
const MAX_WAIT_TIME_TICKET: u64 = 60 * 5;

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
    /// Queries given node for nodes advertising a topic hash
    TopicQuery(TopicHash, oneshot::Sender<Result<Vec<Enr>, RequestError>>),
    /// RegisterTopic publishes this node as an advertiser for a topic at given node
    RegisterTopic(TopicHash),
    ActiveTopics(oneshot::Sender<Result<Ads, RequestError>>),
    RemoveTopic(TopicHash, oneshot::Sender<Result<String, RequestError>>),
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

    /// RPC requests that have been sent and are awaiting a response. Some requests are linked to a
    /// query.
    active_requests: FnvHashMap<RequestId, ActiveRequest>,

    /// Keeps track of the number of responses received from a NODES response.
    active_nodes_responses: HashMap<NodeId, NodesResponse>,

    /// Keeps track of the number of responses received from a NODES response.
    active_adnodes_responses: HashMap<NodeId, NodesResponse>,

    /// Keeps track of the 2 expected responses, NODES and ADNODES that should be received from a
    /// TOPICQUERY request.
    topic_query_responses: HashMap<NodeId, TopicQueryResponseState>,

    /// Keeps track of the 3 expected responses, TICKET and NODES that should be received from a
    /// REGTOPIC request and REGCONFIRMATION that may be received.
    active_regtopic_requests: ActiveRegtopicRequests,

    /// A map of votes nodes have made about our external IP address. We accept the majority.
    ip_votes: Option<IpVote>,

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

    /// A channel that the service emits events on.
    event_stream: Option<mpsc::Sender<Discv5Event>>,

    /// Ads advertised locally for other nodes.
    ads: Ads,

    /// Topics tracks registration attempts of the topics to advertise on
    /// other nodes.
    topics: HashMap<TopicHash, HashMap<u64, HashMap<NodeId, RegistrationState>>>,

    /// KBuckets per topic hash.
    topics_kbuckets: HashMap<TopicHash, KBucketsTable<NodeId, Enr>>,

    /// Ads currently advertised on other nodes.
    active_topics: Ads,

    /// Tickets received by other nodes.
    tickets: Tickets,

    /// Locally issued tickets returned by nodes pending registration for free local ad slots.
    ticket_pools: TicketPools,

    /// Locally initiated topic query requests in process.
    active_topic_queries: ActiveTopicQueries,
}

pub enum TopicQueryResponseState {
    Start,
    Nodes,
    AdNodes,
}

pub enum RegistrationState {
    Confirmed(Instant),
    Ticket,
}

pub struct ActiveTopicQuery {
    // A NodeId mapped to false is waiting for a response or failed request.
    queried_peers: HashMap<NodeId, bool>,
    // An ad returned by multiple peers is only included once.
    results: HashMap<NodeId, Enr>,
    callback: Option<oneshot::Sender<Result<Vec<Enr>, RequestError>>>,
    start: Instant,
}

pub struct ActiveTopicQueries {
    queries: HashMap<TopicHash, ActiveTopicQuery>,
    time_out: Duration,
    num_results: usize,
}

impl ActiveTopicQueries {
    pub fn new(time_out: Duration, num_results: usize) -> Self {
        ActiveTopicQueries {
            queries: HashMap::new(),
            time_out,
            num_results,
        }
    }
}

pub enum TopicQueryState {
    Finished(TopicHash),
    TimedOut(TopicHash),
    Unsatisfied(TopicHash, usize),
}

impl Stream for ActiveTopicQueries {
    type Item = TopicQueryState;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        for (topic_hash, query) in self.queries.iter() {
            if query.results.len() >= self.num_results {
                return Poll::Ready(Some(TopicQueryState::Finished(*topic_hash)));
            } else if query.start.elapsed() >= self.time_out {
                warn!(
                    "TOPICQUERY timed out. Only {} ads found for topic hash.",
                    query.results.len()
                );
                return Poll::Ready(Some(TopicQueryState::TimedOut(*topic_hash)));
            } else {
                let exhausted_peers = query
                    .queried_peers
                    .iter()
                    .filter(|(_peer, return_status)| **return_status)
                    .count();
                // If all peers have responded or failed the request and we still did not
                // obtain enough results, the query is in TopicQueryState::Unsatisfied.
                if exhausted_peers >= query.queried_peers.len() {
                    return Poll::Ready(Some(TopicQueryState::Unsatisfied(
                        *topic_hash,
                        query.results.len(),
                    )));
                }
            }
        }
        Poll::Pending
    }
}

/// Active RPC request awaiting a response from the handler.
pub struct ActiveRequest {
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
    /// A response from a TALK request.
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
    ) -> Result<(oneshot::Sender<()>, mpsc::Sender<ServiceRequest>), Error> {
        // process behaviour-level configuration parameters
        let ip_votes = if config.enr_update {
            Some(IpVote::new(
                config.enr_peer_update_min,
                config.vote_duration,
            ))
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

        let ads = match Ads::new(Duration::from_secs(60 * 15), 100, 50000) {
            Ok(ads) => ads,
            Err(e) => {
                return Err(Error::new(ErrorKind::InvalidInput, e));
            }
        };
        let active_topics = match Ads::new(Duration::from_secs(60 * 15), 100, 50000) {
            Ok(ads) => ads,
            Err(e) => {
                return Err(Error::new(ErrorKind::InvalidInput, e));
            }
        };

        let ticket_key: [u8; 16] = rand::random();
        match local_enr
            .write()
            .insert("ticket_key", &ticket_key, &enr_key.write())
        {
            Ok(_) => {}
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, format!("{:?}", e)));
            }
        }

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
                    active_adnodes_responses: HashMap::new(),
                    topic_query_responses: HashMap::new(),
                    active_regtopic_requests: ActiveRegtopicRequests::default(),
                    ip_votes,
                    handler_send,
                    handler_recv,
                    handler_exit: Some(handler_exit),
                    peers_to_ping: HashSetDelay::new(config.ping_interval),
                    discv5_recv,
                    event_stream: None,
                    ads,
                    topics: HashMap::new(),
                    topics_kbuckets: HashMap::new(),
                    active_topics,
                    tickets: Tickets::new(Duration::from_secs(60 * 15)),
                    ticket_pools: TicketPools::default(),
                    active_topic_queries: ActiveTopicQueries::new(
                        config.topic_query_timeout,
                        config.max_nodes_response,
                    ),
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
                                    self.start_findnode_query(target_node, Some(callback));
                                }
                                QueryKind::Predicate { target_node, target_peer_no, predicate } => {
                                    self.start_predicate_query(target_node, target_peer_no, predicate, Some(callback));
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
                        ServiceRequest::TopicQuery(topic_hash, callback) => {
                            // If we look up the topic hash for the first time we initialise its kbuckets.
                            if let Entry::Vacant(_) = self.topics_kbuckets.entry(topic_hash) {
                                trace!("Init kbuckets for topic hash {}", topic_hash);
                                // NOTE: Currently we don't expose custom filter support in the configuration. Users can
                                // optionally use the IP filter via the ip_limit configuration parameter. In the future, we
                                // may expose this functionality to the users if there is demand for it.
                                let (table_filter, bucket_filter) = if self.config.ip_limit {
                                    (
                                        Some(Box::new(kbucket::IpTableFilter) as Box<dyn kbucket::Filter<Enr>>),
                                        Some(Box::new(kbucket::IpBucketFilter) as Box<dyn kbucket::Filter<Enr>>),
                                    )
                                } else {
                                    (None, None)
                                };

                                let mut kbuckets = KBucketsTable::new(
                                    NodeId::new(&topic_hash.as_bytes()).into(),
                                    Duration::from_secs(60),
                                    self.config.incoming_bucket_limit,
                                    table_filter,
                                    bucket_filter,
                                );
                                {
                                    let mut local_routing_table = self.kbuckets.write();
                                    Service::new_connections_disconnected(&mut kbuckets, topic_hash, local_routing_table.iter().map(|entry| entry.node.value.clone()));
                                }
                                self.topics_kbuckets.insert(topic_hash, kbuckets);
                            }
                            self.send_topic_queries(topic_hash, self.config.max_nodes_response, Some(callback));
                        }
                        ServiceRequest::RegisterTopic(topic_hash) => {
                            if self.topics.insert(topic_hash, HashMap::new()).is_some() {
                                warn!("This topic is already being advertised");
                            } else {
                                // NOTE: Currently we don't expose custom filter support in the configuration. Users can
                                // optionally use the IP filter via the ip_limit configuration parameter. In the future, we
                                // may expose this functionality to the users if there is demand for it.
                                let (table_filter, bucket_filter) = if self.config.ip_limit {
                                    (
                                        Some(Box::new(kbucket::IpTableFilter) as Box<dyn kbucket::Filter<Enr>>),
                                        Some(Box::new(kbucket::IpBucketFilter) as Box<dyn kbucket::Filter<Enr>>),
                                    )
                                } else {
                                    (None, None)
                                };

                                debug!("Initiating kbuckets for topic hash {}", topic_hash);
                                let mut kbuckets = KBucketsTable::new(
                                    NodeId::new(&topic_hash.as_bytes()).into(),
                                    Duration::from_secs(60),
                                    self.config.incoming_bucket_limit,
                                    table_filter,
                                    bucket_filter,
                                );
                                debug!("Adding {} entries from local routing table to topic's kbuckets", self.kbuckets.write().iter().count());

                                {
                                    let mut local_routing_table = self.kbuckets.write();
                                    Service::new_connections_disconnected(&mut kbuckets, topic_hash, local_routing_table.iter().map(|entry| entry.node.value.clone()));
                                }
                                self.topics_kbuckets.insert(topic_hash, kbuckets);
                                METRICS.topics_to_publish.store(self.topics.len(), Ordering::Relaxed);

                                self.send_register_topics(topic_hash);
                            }
                        }
                        ServiceRequest::ActiveTopics(callback) => {
                            if callback.send(Ok(self.active_topics.clone())).is_err() {
                                error!("Failed to return active topics");
                            }
                        }
                        ServiceRequest::RemoveTopic(topic_hash, callback) => {
                            if self.topics.remove(&topic_hash).is_some() {
                                METRICS.topics_to_publish.store(self.topics.len(), Ordering::Relaxed);
                                if callback.send(Ok(base64::encode(topic_hash.as_bytes()))).is_err() {
                                    error!("Failed to return the removed topic");
                                }
                            }
                        }
                    }
                }
                Some(event) = self.handler_recv.recv() => {
                    match event {
                        HandlerOut::Established(enr, direction) => {
                            self.inject_session_established(enr, direction, None);
                        }
                        HandlerOut::EstablishedTopic(enr, direction, topic_hash) => {
                            self.inject_session_established(enr, direction, Some(topic_hash));
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
                                    warn!("Failed to send who are you to unknonw enr peer {}", e);
                                }
                            }
                        }
                        HandlerOut::RequestFailed(request_id, error) => {
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
                Some(event) = Service::bucket_maintenance_poll_topics(self.topics_kbuckets.iter_mut()) => {
                    self.send_event(event);
                }
                query_event = Service::query_event_poll(&mut self.queries) => {
                    match query_event {
                        QueryEvent::Waiting(query_id, node_id, request_body) => {
                            self.send_rpc_query(query_id, node_id, *request_body);
                        }
                        // Note: Currently the distinction between a timed-out query and a finished
                        // query is superfluous, however it may be useful in future versions.
                        QueryEvent::Finished(query) | QueryEvent::TimedOut(query) => {
                            let id = query.id();
                            let mut result = query.into_result();
                            // obtain the ENR's for the resulting nodes
                            let mut found_enrs = Vec::new();
                            for node_id in result.closest_peers {
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

                            if let Some(callback) = result.target.callback {
                                if callback.send(found_enrs).is_err() {
                                    warn!("Callback dropped for query {}. Results dropped", *id);
                                }
                            }
                        }
                    }
                }
                Some(Ok(node_id)) = self.peers_to_ping.next() => {
                    // If the node is in the routing table, Ping it and re-queue the node.
                    let key = kbucket::Key::from(node_id);
                    let enr =  {
                        if let kbucket::Entry::Present(entry, _) = self.kbuckets.write().entry(&key) {
                        // The peer is in the routing table, ping it and re-queue the ping
                        self.peers_to_ping.insert(node_id);
                        Some(entry.value().clone())
                        } else { None }
                    };

                    if let Some(enr) = enr {
                        self.send_ping(enr);
                    }
                }
                Some(Ok((active_topic, active_ticket))) = self.tickets.next() => {
                    let enr = self.local_enr.read().clone();
                    // When the ticket time expires a new regtopic request is automatically sent
                    // to the ticket issuer.
                    self.reg_topic_request(active_ticket.contact(), active_topic.topic(), enr, Some(active_ticket.ticket()));
                }
                Some(Ok((topic, ticket_pool))) = self.ticket_pools.next() => {
                    // Select ticket with longest cummulative wait time.
                    if let Some(pool_ticket) = ticket_pool.values().max_by_key(|pool_ticket| pool_ticket.ticket().cum_wait()) {
                        self.ads.insert(pool_ticket.node_record().clone(), topic).ok();
                        NodeContact::try_from_enr(pool_ticket.node_record().clone(), self.config.ip_mode).map(|contact| {
                            self.send_regconfirmation_response(contact.node_address(), pool_ticket.req_id().clone(), topic);
                        }).ok();
                        METRICS.hosted_ads.store(self.ads.len(), Ordering::Relaxed);
                    }
                }
                Some(topic_query_progress) = self.active_topic_queries.next() => {
                    match topic_query_progress {
                        TopicQueryState::Finished(topic_hash) | TopicQueryState::TimedOut(topic_hash) => {
                            if let Some(query) = self.active_topic_queries.queries.remove(&topic_hash) {
                                if let Some(callback) = query.callback {
                                    if callback.send(Ok(query.results.into_values().collect::<Vec<_>>())).is_err() {
                                        warn!("Callback dropped for topic query {}. Results dropped", topic_hash);
                                    }
                                }
                            }
                        },
                        TopicQueryState::Unsatisfied(topic_hash, num_query_peers) => {
                            self.send_topic_queries(topic_hash, num_query_peers, None);
                        }
                    }
                }
            }
        }
    }

    fn send_register_topics(&mut self, topic_hash: TopicHash) {
        if let Entry::Occupied(ref mut kbuckets) = self.topics_kbuckets.entry(topic_hash) {
            let reg_attempts = self.topics.entry(topic_hash).or_default();
            // Remove expired ads
            let mut new_reg_peers = Vec::new();
            // WARNING! This currently only works as long as buckets range is one bit
            for (index, bucket) in kbuckets.get_mut().buckets_iter().enumerate() {
                // Remove expired registrations
                if let Entry::Occupied(ref mut entry) = reg_attempts.entry(index as u64) {
                    let registrations = entry.get_mut();
                    registrations.retain(|_, reg_attempt| {
                        if let RegistrationState::Confirmed(insert_time) = reg_attempt {
                            insert_time.elapsed() >= Duration::from_secs(15 * 60)
                        } else {
                            false
                        }
                    });
                }
                let registrations = reg_attempts.entry(index as u64).or_default();
                // The count of active registration attempts after expired adds have been removed
                if registrations.len() < self.config.max_nodes_response
                    && registrations.len() != bucket.num_entries()
                {
                    let mut new_peers = Vec::new();
                    for peer in bucket.iter() {
                        if new_peers.len() + registrations.len() >= self.config.max_nodes_response {
                            break;
                        }
                        if let Entry::Vacant(_) = registrations.entry(*peer.key.preimage()) {
                            debug!("Found new reg peer. Peer: {:?}", peer.key.preimage());
                            new_peers.push(peer.value.clone())
                        }
                    }
                    new_reg_peers.append(&mut new_peers);
                }
            }
            for peer in new_reg_peers {
                let local_enr = self.local_enr.read().clone();
                if let Ok(node_contact) = NodeContact::try_from_enr(peer, self.config.ip_mode)
                    .map_err(|e| error!("Failed to send REGTOPIC to peer. Error: {:?}", e))
                {
                    self.reg_topic_request(node_contact, topic_hash, local_enr.clone(), None);
                }
            }
        } else {
            debug_unreachable!("Broken invariant, a kbuckets table should exist for topic hash");
        }
    }

    /// Internal function that starts a query.
    fn send_topic_queries(
        &mut self,
        topic_hash: TopicHash,
        num_query_peers: usize,
        callback: Option<oneshot::Sender<Result<Vec<Enr>, RequestError>>>,
    ) {
        let query = self
            .active_topic_queries
            .queries
            .entry(topic_hash)
            .or_insert(ActiveTopicQuery {
                queried_peers: HashMap::new(),
                results: HashMap::new(),
                callback,
                start: Instant::now(),
            });
        let queried_peers = query.queried_peers.clone();
        if let Entry::Occupied(kbuckets) = self.topics_kbuckets.entry(topic_hash) {
            let mut peers = kbuckets.get().clone();
            trace!(
                "Found {} peers in kbuckets of topic hash {}",
                peers.iter().count(),
                topic_hash
            );
            // Prefer querying nodes further away, starting at distance 256 by to avoid hotspots
            let new_query_peers_iter = peers.iter().rev().filter_map(|entry| {
                (!queried_peers.contains_key(entry.node.key.preimage())).then(|| {
                    query
                        .queried_peers
                        .entry(*entry.node.key.preimage())
                        .or_default();
                    entry.node.value
                })
            });
            let mut new_query_peers = Vec::new();
            for enr in new_query_peers_iter {
                new_query_peers.push(enr);
                if new_query_peers.len() < num_query_peers {
                    break;
                }
            }
            trace!("Sending TOPICQUERYs to {} new peers", new_query_peers.len());
            for enr in new_query_peers {
                if let Ok(node_contact) =
                    NodeContact::try_from_enr(enr.clone(), self.config.ip_mode)
                        .map_err(|e| error!("Failed to send TOPICQUERY to peer. Error: {:?}", e))
                {
                    self.topic_query_request(node_contact, topic_hash);
                }
            }
        } else {
            debug_unreachable!("Broken invariant, a kbuckets table should exist for topic hash");
        }
    }

    /// Internal function that starts a query.
    fn start_findnode_query(
        &mut self,
        target_node: NodeId,
        callback: Option<oneshot::Sender<Vec<Enr>>>,
    ) {
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
                // Add the known ENR's to the untrusted list
                target.untrusted_enrs.push(closest.value);
                // Add the key to the list for the query
                known_closest_peers.push(closest.key);
            }
        }

        if known_closest_peers.is_empty() {
            warn!("No known_closest_peers found. Return empty result without sending query.");
            if let Some(callback) = target.callback {
                if callback.send(vec![]).is_err() {
                    warn!("Failed to callback");
                }
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
        callback: Option<oneshot::Sender<Vec<Enr>>>,
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
                // Add the known ENR's to the untrusted list
                target.untrusted_enrs.push(closest.value.clone());
                // Add the key to the list for the query
                known_closest_peers.push(closest.into());
            }
        };

        if known_closest_peers.is_empty() {
            warn!("No known_closest_peers found. Return empty result without sending query.");
            if let Some(callback) = target.callback {
                if callback.send(vec![]).is_err() {
                    warn!("Failed to callback");
                }
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
        debug!("Received RPC request: {} from: {}", req.body, node_address);
        let id = req.id;
        match req.body {
            RequestBody::FindNode { distances } => {
                self.send_find_nodes_response(node_address, id, distances);
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
                    // don't know of the ENR, request the update
                    _ => {}
                }
                if let Some(enr) = to_request_enr {
                    match NodeContact::try_from_enr(enr, self.config.ip_mode) {
                        Ok(contact) => {
                            self.request_enr(contact, None);
                        }
                        Err(NonContactable { enr }) => {
                            error!(
                                "Stored ENR is not contactable! This should never happen {}",
                                enr
                            );
                            #[cfg(debug_assertions)]
                            panic!("Stored ENR is not contactable. {}", enr);
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
            RequestBody::RegisterTopic { topic, enr, ticket } => {
                // Drop if request tries to advertise another node than sender
                if enr.node_id() == node_address.node_id
                    && enr.udp4_socket().map(SocketAddr::V4) == Some(node_address.socket_addr)
                {
                    debug!("Sending NODES response to REGTOPIC");
                    self.send_find_topic_nodes_response(
                        topic,
                        node_address.clone(),
                        id.clone(),
                        "REGTOPIC",
                    );

                    // The current wait time for a given topic.
                    let wait_time = self
                        .ads
                        .ticket_wait_time(topic)
                        .unwrap_or(Duration::from_secs(0));

                    let mut new_ticket = Ticket::new(
                        node_address.node_id,
                        node_address.socket_addr.ip(),
                        topic,
                        tokio::time::Instant::now(),
                        wait_time,
                        Duration::from_secs(0),
                    );

                    if !ticket.is_empty() {
                        let decoded_enr = self
                            .local_enr
                            .write()
                            .to_base64()
                            .parse::<Enr>()
                            .map_err(|e| {
                                error!("Failed to decrypt ticket in REGTOPIC request. Error: {}", e)
                            });
                        if let Ok(decoded_enr) = decoded_enr {
                            if let Some(ticket_key) = decoded_enr.get("ticket_key") {
                                let decrypted_ticket = {
                                    let aead = Aes128Gcm::new(GenericArray::from_slice(ticket_key));
                                    let payload = Payload {
                                        msg: &ticket,
                                        aad: b"",
                                    };
                                    aead.decrypt(GenericArray::from_slice(&[1u8; 12]), payload)
                                        .map_err(|e| {
                                            error!(
                                                "Failed to decrypt ticket in REGTOPIC request. Error: {}",
                                                e
                                            )
                                        })
                                };
                                if let Ok(decrypted_ticket) = decrypted_ticket {
                                    Ticket::decode(&decrypted_ticket)
                                        .map_err(|e| {
                                            error!(
                                                "Failed to decode ticket in REGTOPIC request. Error: {}",
                                                e
                                            )
                                        })
                                        .map(|ticket| {
                                            if let Some(ticket) = ticket {
                                                // A ticket is always be issued upon receiving a REGTOPIC request, even if there is no
                                                // wait time for the ad slot. See discv5 spec. This node will not store tickets received 
                                                // with wait time 0.
                                                new_ticket.set_cum_wait(ticket.cum_wait());
                                                self.send_ticket_response(
                                                    node_address,
                                                    id.clone(),
                                                    new_ticket.clone(),
                                                    wait_time,
                                                );
                                                // If current wait time is 0, the ticket is added to the matching ticket pool.
                                                if wait_time <= Duration::from_secs(0) {
                                                    // Drop if src_node_id, src_ip and topic derived from node_address and request
                                                    // don't match those in ticket. For example if a malicious node tries to use
                                                    // another ticket issued by us.
                                                    if ticket == new_ticket {
                                                        self.ticket_pools.insert(enr, id, ticket);
                                                    }
                                                }
                                            }
                                        })
                                        .ok();
                                }
                            }
                        }
                    } else {
                        debug!("Sending TICKET response");
                        // A ticket is always be issued upon receiving a REGTOPIC request, even if there is no
                        // wait time for the ad slot. See discv5 spec. This node will not store tickets received
                        // with wait time 0.
                        self.send_ticket_response(
                            node_address,
                            id.clone(),
                            new_ticket.clone(),
                            wait_time,
                        );
                        // If current wait time is 0, the ticket is added to the matching ticket pool.
                        if wait_time <= Duration::from_secs(0) {
                            self.ticket_pools.insert(enr, id, new_ticket);
                        }
                    }
                } else {
                    debug!("REGTOPIC enr does not match request sender's enr. Nodes can only register themselves.");
                }
            }
            RequestBody::TopicQuery { topic } => {
                trace!("Sending TOPICQUERY find nodes response");
                self.send_find_topic_nodes_response(
                    topic,
                    node_address.clone(),
                    id.clone(),
                    "TOPICQUERY",
                );
                trace!("Sending TOPICQUERY AD nodes response");
                self.send_topic_query_nodes_response(node_address, id, topic);
            }
        }
    }

    /// Processes an RPC response from a peer.
    fn handle_rpc_response(&mut self, node_address: NodeAddress, response: Response) {
        // verify we know of the rpc_id
        let id = response.id.clone();

        let active_request = if let Some(active_request) = self.active_requests.remove(&id) {
            Some(active_request)
        } else {
            self.active_regtopic_requests.remove(&id)
        };

        if let Some(mut active_request) = active_request {
            debug!(
                "Received RPC response: {} to request: {} from: {}",
                response.body, active_request.request_body, active_request.contact
            );

            // Check that the responder matches the expected request

            let expected_node_address = active_request.contact.node_address();
            if expected_node_address != node_address {
                error!("Received a response from an unexpected address. Expected {}, received {}, request_id {}", expected_node_address, node_address, id);
                #[cfg(debug_assertions)]
                panic!("Handler returned a response not matching the used socket addr");
                #[cfg(not(debug_assertions))]
                return;
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

                    let topic_radius = (1..self.config.topic_radius + 1).collect();
                    // These are sanitized and ordered
                    let distances_requested = match &active_request.request_body {
                        RequestBody::FindNode { distances } => distances,
                        RequestBody::TopicQuery { .. } | RequestBody::RegisterTopic { .. } => {
                            &topic_radius
                        }
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

                    // The distances we send are sanitized an ordered.
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
                            warn!(
                                "Peer sent invalid ENR. Blacklisting {}",
                                active_request.contact
                            );
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
                        // if there are more responses coming, store the nodes and wait for
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
                            match active_request.request_body {
                                RequestBody::RegisterTopic { .. } => {
                                    self.active_regtopic_requests.reinsert(id);
                                }
                                _ => {
                                    self.active_requests.insert(id, active_request);
                                }
                            }
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

                    match active_request.request_body {
                        RequestBody::TopicQuery { topic } => {
                            if let Some(kbuckets) = self.topics_kbuckets.get_mut(&topic) {
                                Service::new_connections_disconnected(
                                    kbuckets,
                                    topic,
                                    nodes.into_iter(),
                                );
                                let response_state = self
                                    .topic_query_responses
                                    .entry(node_id)
                                    .or_insert(TopicQueryResponseState::Start);

                                match response_state {
                                    TopicQueryResponseState::Start => {
                                        *response_state = TopicQueryResponseState::Nodes;
                                        self.active_requests.insert(id, active_request);
                                    }
                                    TopicQueryResponseState::AdNodes => {
                                        self.topic_query_responses.remove(&node_id);
                                    }
                                    TopicQueryResponseState::Nodes => {
                                        debug_unreachable!("No more NODES responses should be received if TOPICQUERY response is in Nodes state.")
                                    }
                                }
                            }
                        }
                        RequestBody::RegisterTopic {
                            topic,
                            enr: _,
                            ticket: _,
                        } => {
                            if let Some(kbuckets) = self.topics_kbuckets.get_mut(&topic) {
                                Service::new_connections_disconnected(
                                    kbuckets,
                                    topic,
                                    nodes.into_iter(),
                                );
                            }
                        }
                        RequestBody::FindNode { .. } => {
                            self.discovered(&node_id, nodes, active_request.query_id)
                        }
                        _ => debug_unreachable!(
                            "Only TOPICQUERY, REGTOPIC and FINDNODE requests expect NODES response"
                        ),
                    }
                }
                ResponseBody::AdNodes { total, mut nodes } => {
                    // handle the case that there is more than one response
                    if total > 1 {
                        let mut current_response = self
                            .active_adnodes_responses
                            .remove(&node_id)
                            .unwrap_or_default();

                        debug!(
                            "ADNODES Response: {} of {} received",
                            current_response.count, total
                        );
                        // if there are more responses coming, store the nodes and wait for
                        // another response
                        // We allow for implementations to send at a minimum 3 nodes per response.
                        // We allow for the number of nodes to be returned as the maximum we emit.
                        if current_response.count < self.config.max_nodes_response / 3 + 1
                            && (current_response.count as u64) < total
                        {
                            current_response.count += 1;

                            current_response.received_nodes.append(&mut nodes);
                            self.active_adnodes_responses
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
                        "Received a ADNODES response of len: {}, total: {}, from: {}",
                        nodes.len(),
                        total,
                        active_request.contact
                    );
                    // note: If a peer sends an initial NODES response with a total > 1 then
                    // in a later response sends a response with a total of 1, all previous nodes
                    // will be ignored.
                    // ensure any mapping is removed in this rare case
                    self.active_adnodes_responses.remove(&node_id);

                    if let RequestBody::TopicQuery { topic } = active_request.request_body {
                        if let Some(query) = self.active_topic_queries.queries.get_mut(&topic) {
                            nodes.into_iter().for_each(|enr| {
                                query.results.insert(enr.node_id(), enr);
                            });
                        }
                        let response_state = self
                            .topic_query_responses
                            .entry(node_id)
                            .or_insert(TopicQueryResponseState::Start);

                        match response_state {
                            TopicQueryResponseState::Start => {
                                *response_state = TopicQueryResponseState::AdNodes;
                                self.active_requests.insert(id, active_request);
                            }
                            TopicQueryResponseState::Nodes => {
                                self.topic_query_responses.remove(&node_id);
                            }
                            TopicQueryResponseState::AdNodes => {
                                debug_unreachable!("No more ADNODES responses should be received if TOPICQUERY response is in AdNodes state.")
                            }
                        }
                    }
                }
                ResponseBody::Pong { enr_seq, ip, port } => {
                    let socket = SocketAddr::new(ip, port);
                    // perform ENR majority-based update if required.

                    // Only count votes that from peers we have contacted.
                    let key: kbucket::Key<NodeId> = node_id.into();
                    let should_count = match self.kbuckets.write().entry(&key) {
                        kbucket::Entry::Present(_, status)
                            if status.is_connected() && !status.is_incoming() =>
                        {
                            true
                        }
                        _ => false,
                    };

                    if should_count {
                        // get the advertised local addresses
                        let (local_ip4_socket, local_ip6_socket) = {
                            let local_enr = self.local_enr.read();
                            (local_enr.udp4_socket(), local_enr.udp6_socket())
                        };

                        if let Some(ref mut ip_votes) = self.ip_votes {
                            ip_votes.insert(node_id, socket);
                            let (maybe_ip4_majority, maybe_ip6_majority) = ip_votes.majority();

                            let new_ip4 = maybe_ip4_majority.and_then(|majority| {
                                if Some(majority) != local_ip4_socket {
                                    Some(majority)
                                } else {
                                    None
                                }
                            });
                            let new_ip6 = maybe_ip6_majority.and_then(|majority| {
                                if Some(majority) != local_ip6_socket {
                                    Some(majority)
                                } else {
                                    None
                                }
                            });

                            if new_ip4.is_some() || new_ip6.is_some() {
                                let mut updated = false;

                                // Check if our advertised IPV6 address needs to be updated.
                                if let Some(new_ip6) = new_ip6 {
                                    info!("Local UDP ip6 socket updated to: {}", new_ip6);
                                    let new_ip6: SocketAddr = new_ip6.into();
                                    self.send_event(Discv5Event::SocketUpdated(new_ip6));
                                    updated |= self
                                        .local_enr
                                        .write()
                                        .set_udp_socket(new_ip6, &self.enr_key.read())
                                        .is_ok();
                                }
                                if let Some(new_ip4) = new_ip4 {
                                    info!("Local UDP socket updated to: {}", new_ip4);
                                    let new_ip4: SocketAddr = new_ip4.into();
                                    self.send_event(Discv5Event::SocketUpdated(new_ip4));
                                    updated |= self
                                        .local_enr
                                        .write()
                                        .set_udp_socket(new_ip4, &self.enr_key.read())
                                        .is_ok();
                                }
                                if updated {
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
                        self.connection_updated(node_id, ConnectionStatus::PongReceived(enr), None);
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
                ResponseBody::Ticket {
                    ticket,
                    wait_time,
                    topic,
                } => {
                    if wait_time <= MAX_WAIT_TIME_TICKET && wait_time > 0 {
                        self.tickets
                            .insert(
                                active_request.contact,
                                ticket,
                                Duration::from_secs(wait_time),
                                topic,
                            )
                            .ok();
                        let peer_key: kbucket::Key<NodeId> = node_id.into();
                        let topic_key: kbucket::Key<NodeId> = NodeId::new(&topic.as_bytes()).into();
                        if let Some(distance) = peer_key.log2_distance(&topic_key) {
                            let registration_attempts = self.topics.entry(topic).or_default();
                            registration_attempts
                                .entry(distance)
                                .or_default()
                                .entry(node_id)
                                .or_insert(RegistrationState::Ticket);
                            self.send_register_topics(topic);
                        }
                    }
                }
                ResponseBody::RegisterConfirmation { topic } => {
                    if let Some(enr) = active_request.contact.enr() {
                        let now = Instant::now();
                        let peer_key: kbucket::Key<NodeId> = node_id.into();
                        let topic_key: kbucket::Key<NodeId> = NodeId::new(&topic.as_bytes()).into();
                        if let Some(distance) = peer_key.log2_distance(&topic_key) {
                            let registration_attempts = self.topics.entry(topic).or_default();
                            registration_attempts
                                .entry(distance)
                                .or_default()
                                .entry(node_id)
                                .or_insert(RegistrationState::Confirmed(now));

                            let _ = self.active_topics.insert(enr, topic).map_err(|e| {
                                error!("Couldn't insert topic into active topics. Error: {}.", e)
                            });

                            METRICS
                                .active_ads
                                .store(self.active_topics.len(), Ordering::Relaxed);
                            METRICS
                                .active_regtopic_req
                                .store(self.active_regtopic_requests.len(), Ordering::Relaxed);
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
    fn send_ping(&mut self, enr: Enr) {
        match NodeContact::try_from_enr(enr, self.config.ip_mode) {
            Ok(contact) => {
                let request_body = RequestBody::Ping {
                    enr_seq: self.local_enr.read().seq(),
                };
                let active_request = ActiveRequest {
                    contact,
                    request_body,
                    query_id: None,
                    callback: None,
                };
                self.send_rpc_request(active_request);
            }
            Err(NonContactable { enr }) => error!("Trying to ping a non-contactable peer {}", enr),
        }
    }

    /// Ping all peers that are connected in the routing table.
    fn ping_connected_peers(&mut self) {
        // maintain the ping interval
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

    /// Requests a node to advertise the sending node for a given topic hash.
    fn reg_topic_request(
        &mut self,
        contact: NodeContact,
        topic: TopicHash,
        enr: Enr,
        ticket: Option<Vec<u8>>,
    ) {
        let ticket_bytes = if let Some(ticket) = ticket {
            ticket
        } else {
            Vec::new()
        };
        let request_body = RequestBody::RegisterTopic {
            topic,
            enr,
            ticket: ticket_bytes,
        };
        self.send_rpc_request(ActiveRequest {
            contact,
            request_body,
            query_id: None,
            callback: None,
        });
    }

    /// Queries a node for the ads that node currently advertises for a given topic.
    fn topic_query_request(&mut self, contact: NodeContact, topic: TopicHash) {
        let request_body = RequestBody::TopicQuery { topic };

        let active_request = ActiveRequest {
            contact,
            request_body,
            query_id: None,
            callback: None,
        };
        self.send_rpc_request(active_request);
    }

    /// The response sent to every REGTOPIC request, as according to spec.
    fn send_ticket_response(
        &mut self,
        node_address: NodeAddress,
        rpc_id: RequestId,
        ticket: Ticket,
        wait_time: Duration,
    ) {
        self.local_enr
            .write()
            .to_base64()
            .parse::<Enr>()
            .map_err(|e| error!("Failed to send TICKET response: {}", e))
            .map(|decoded_enr| {
                if let Some(ticket_key) = decoded_enr.get("ticket_key") {
                    let aead = Aes128Gcm::new(GenericArray::from_slice(ticket_key));
                    let payload = Payload {
                        msg: &ticket.encode(),
                        aad: b"",
                    };
                    aead.encrypt(GenericArray::from_slice(&[1u8; 12]), payload)
                        .map_err(|e| error!("Failed to send TICKET response: {}", e))
                        .map(|encrypted_ticket| {
                            let response = Response {
                                id: rpc_id,
                                body: ResponseBody::Ticket {
                                    ticket: encrypted_ticket,
                                    wait_time: wait_time.as_secs(),
                                    topic: ticket.topic(),
                                },
                            };
                            trace!(
                                "Sending TICKET response to: {}. Response: {} ",
                                node_address,
                                response
                            );
                            let _ = self
                                .handler_send
                                .send(HandlerIn::Response(node_address, Box::new(response)));
                        })
                        .ok();
                }
            })
            .ok();
    }

    /// The response sent to a node which is selected out of a ticket pool of registrants
    /// for a free ad slot.
    fn send_regconfirmation_response(
        &mut self,
        node_address: NodeAddress,
        rpc_id: RequestId,
        topic: TopicHash,
    ) {
        let response = Response {
            id: rpc_id,
            body: ResponseBody::RegisterConfirmation { topic },
        };
        trace!(
            "Sending REGCONFIRMATION response to: {}. Response: {} ",
            node_address,
            response
        );
        let _ = self
            .handler_send
            .send(HandlerIn::Response(node_address, Box::new(response)));
    }

    /// Answer to a topic query containing the nodes currently advertised for the
    /// requested topic if any.
    fn send_topic_query_nodes_response(
        &mut self,
        node_address: NodeAddress,
        rpc_id: RequestId,
        topic: TopicHash,
    ) {
        let nodes_to_send = self
            .ads
            .get_ad_nodes(topic)
            .map(|ad| ad.node_record().clone())
            .collect();
        self.send_nodes_response(nodes_to_send, node_address, rpc_id, "TOPICQUERY ADS");
    }

    fn send_find_topic_nodes_response(
        &mut self,
        topic: TopicHash,
        node_address: NodeAddress,
        id: RequestId,
        req_type: &str,
    ) {
        let local_key: kbucket::Key<NodeId> = self.local_enr.read().node_id().into();
        let topic_key: kbucket::Key<NodeId> = NodeId::new(&topic.as_bytes()).into();
        let distance_to_topic = local_key.log2_distance(&topic_key);

        let mut closest_peers: Vec<Enr> = Vec::new();
        if let Some(distance) = distance_to_topic {
            self.kbuckets
                .write()
                .nodes_by_distances(&[distance], self.config.max_nodes_response)
                .iter()
                .for_each(|entry| closest_peers.push(entry.node.value.clone()));

            if closest_peers.len() < self.config.max_nodes_response {
                for entry in self
                    .kbuckets
                    .write()
                    .nodes_by_distances(
                        &[distance - 1, distance + 1],
                        self.config.max_nodes_response - closest_peers.len(),
                    )
                    .iter()
                {
                    if closest_peers.len() > self.config.max_nodes_response {
                        break;
                    }
                    closest_peers.push(entry.node.value.clone());
                }
            }
        }
        self.send_nodes_response(closest_peers, node_address, id, req_type);
    }

    /// Sends a NODES response, given a list of found ENR's. This function splits the nodes up
    /// into multiple responses to ensure the response stays below the maximum packet size.
    fn send_find_nodes_response(
        &mut self,
        node_address: NodeAddress,
        rpc_id: RequestId,
        mut distances: Vec<u64>,
    ) {
        // NOTE: At most we only allow 5 distances to be sent (see the decoder). If each of these
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
                .nodes_by_distances(distances.as_slice(), self.config.max_nodes_response)
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
        self.send_nodes_response(nodes_to_send, node_address, rpc_id, "FINDNODE");
    }

    fn send_nodes_response(
        &self,
        nodes_to_send: Vec<Enr>,
        node_address: NodeAddress,
        rpc_id: RequestId,
        req_type: &str,
    ) {
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
                "Sending empty {} response to: {}",
                req_type,
                node_address.node_id
            );
            if let Err(e) = self
                .handler_send
                .send(HandlerIn::Response(node_address, Box::new(response)))
            {
                warn!("Failed to send empty {} response {}", req_type, e)
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
                    "Sending {} NODES response to: {}. Response: {} ",
                    req_type,
                    node_address,
                    response
                );
                if let Err(e) = self.handler_send.send(HandlerIn::Response(
                    node_address.clone(),
                    Box::new(response),
                )) {
                    warn!("Failed to send {} response {}", req_type, e)
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
            match NodeContact::try_from_enr(enr, self.config.ip_mode) {
                Ok(contact) => {
                    let active_request = ActiveRequest {
                        contact,
                        request_body,
                        query_id: Some(query_id),
                        callback: None,
                    };
                    self.send_rpc_request(active_request);
                    // Request successfully sent
                    return;
                }
                Err(NonContactable { enr }) => {
                    error!("Query {} has a non contactable enr: {}", *query_id, enr);
                }
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
    fn send_rpc_request(&mut self, active_request: ActiveRequest) -> RequestId {
        // Generate a random rpc_id which is matched per node id
        let id = RequestId::random();
        let request_body = active_request.request_body.clone();
        let request: Request = Request {
            id: id.clone(),
            body: request_body.clone(),
        };
        let contact = active_request.contact.clone();

        debug!("Sending RPC {} to node: {}", request, contact);
        if self
            .handler_send
            .send(HandlerIn::Request(contact, Box::new(request)))
            .is_ok()
        {
            match request_body {
                RequestBody::RegisterTopic { .. } => {
                    self.active_regtopic_requests
                        .insert(id.clone(), active_request);
                    METRICS
                        .active_regtopic_req
                        .store(self.active_regtopic_requests.len(), Ordering::Relaxed);
                }
                _ => {
                    self.active_requests.insert(id.clone(), active_request);
                }
            }
        }
        id
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
    fn discovered(&mut self, source: &NodeId, mut enrs: Vec<Enr>, query_id: Option<QueryId>) {
        let local_id = self.local_enr.read().node_id();
        enrs.retain(|enr| {
            if enr.node_id() == local_id {
                return false;
            }

            // If any of the discovered nodes are in the routing table, and there contains an older ENR, update it.
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

                        return false; // Remove this peer from the discovered list if the update failed
                    }
                }
            } else {
                return false; // Didn't pass the table filter remove the peer
            }

            // The remaining ENRs are used if this request was part of a query. If we are
            // requesting the target of the query, this ENR could be the result of requesting the
            // target-nodes own id. We don't want to add this as a "new" discovered peer in the
            // query, so we remove it from the discovered list here.
            source != &enr.node_id()
        });

        // if this is part of a query, update the query
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
                    }
                    peer_count += 1;
                }
                debug!("{} peers found for query id {:?}", peer_count, query_id);
                query.on_success(source, &enrs)
            } else {
                debug!("Response returned for ended query {:?}", query_id)
            }
        }
    }

    /// Update the connection status of a node in the routing table.
    /// This tracks whether or not we should be pinging peers. Disconnected peers are removed from
    /// the queue and newly added peers to the routing table are added to the queue.
    fn connection_updated(
        &mut self,
        node_id: NodeId,
        new_status: ConnectionStatus,
        topic_hash: Option<TopicHash>,
    ) {
        // Variables to that may require post-processing
        let mut ping_peer = None;
        let mut event_to_send = None;

        let kbuckets_topic = if let Some(topic_hash) = topic_hash {
            if let Some(kbuckets) = self.topics_kbuckets.get_mut(&topic_hash) {
                Some(kbuckets)
            } else {
                debug_unreachable!("A kbuckets table should exist for topic hash");
                None
            }
        } else {
            None
        };

        let key = kbucket::Key::from(node_id);
        match new_status {
            ConnectionStatus::Connected(enr, direction) => {
                // attempt to update or insert the new ENR.
                let status = NodeStatus {
                    state: ConnectionState::Connected,
                    direction,
                };
                let insert_result = if let Some(kbuckets) = kbuckets_topic {
                    kbuckets.insert_or_update(&key, enr, status)
                } else {
                    self.kbuckets.write().insert_or_update(&key, enr, status)
                };
                match insert_result {
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
                let update_result = if let Some(kbuckets) = kbuckets_topic {
                    kbuckets.update_node_status(&key, ConnectionState::Disconnected, None)
                } else {
                    self.kbuckets.write().update_node_status(
                        &key,
                        ConnectionState::Disconnected,
                        None,
                    )
                };
                // If the node has disconnected, remove any ping timer for the node.
                match update_result {
                    UpdateResult::Failed(reason) => match reason {
                        FailureReason::KeyNonExistant => {}
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
                    // NOTE: We don't check the status of this peer. We try and ping outdated peers.
                    Some(entry.value().clone())
                } else {
                    None
                }
            };
            if let Some(enr) = optional_enr {
                self.send_ping(enr)
            }
        }
    }

    /// The equivalent of libp2p `inject_connected()` for a udp session. We have no stream, but a
    /// session key-pair has been negotiated.
    fn inject_session_established(
        &mut self,
        enr: Enr,
        direction: ConnectionDirection,
        topic_hash: Option<TopicHash>,
    ) {
        // Ignore sessions with non-contactable ENRs
        if self.config.ip_mode.get_contactable_addr(&enr).is_none() {
            return;
        }

        let node_id = enr.node_id();
        debug!(
            "Session established with Node: {}, direction: {}",
            node_id, direction
        );
        self.connection_updated(
            node_id,
            ConnectionStatus::Connected(enr, direction),
            topic_hash,
        );
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
                        .unwrap_or_else(|_| debug!("Couldn't send ENR error response to user"));
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
                RequestBody::TopicQuery { topic } => {
                    if let Some(query) = self.active_topic_queries.queries.get_mut(&topic) {
                        if let Some(exhausted) = query.queried_peers.get_mut(&node_id) {
                            *exhausted = true;
                            debug!(
                                "Failed TOPICQUERY request: {} for node: {}, reason {:?} ",
                                active_request.request_body, active_request.contact, error
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

            match active_request.request_body {
                RequestBody::RegisterTopic {
                    topic,
                    enr: _,
                    ticket: _,
                }
                | RequestBody::TopicQuery { topic } => {
                    self.connection_updated(node_id, ConnectionStatus::Disconnected, Some(topic))
                }
                _ => self.connection_updated(node_id, ConnectionStatus::Disconnected, None),
            }
        }
    }

    fn new_connections_disconnected(
        kbuckets: &mut KBucketsTable<NodeId, Enr>,
        topic: TopicHash,
        nodes: impl Iterator<Item = Enr>,
    ) {
        for enr in nodes {
            let peer_key: kbucket::Key<NodeId> = enr.node_id().into();
            match kbuckets.insert_or_update(
                &peer_key,
                enr.clone(),
                NodeStatus {
                    state: ConnectionState::Disconnected,
                    direction: ConnectionDirection::Incoming,
                },
            ) {
                InsertResult::Failed(FailureReason::BucketFull) => {
                    error!("Table full")
                }
                InsertResult::Failed(FailureReason::BucketFilter) => {
                    error!("Failed bucket filter")
                }
                InsertResult::Failed(FailureReason::TableFilter) => {
                    error!("Failed table filter")
                }
                InsertResult::Failed(FailureReason::InvalidSelfUpdate) => {
                    error!("Invalid self update")
                }
                InsertResult::Failed(_) => error!("Failed to insert ENR"),
                _ => debug!(
                    "Insertion of node {} into KBucket of {} was successful",
                    enr.node_id(),
                    topic
                ),
            }
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

    /// A future that maintains the topic kbuckets and inserts nodes when required. This returns the
    /// `Discv5Event::NodeInsertedTopics` variants.
    async fn bucket_maintenance_poll_topics(
        kbuckets: impl Iterator<Item = (&TopicHash, &mut KBucketsTable<NodeId, Enr>)>,
    ) -> Option<Discv5Event> {
        // Drain applied pending entries from the routing table.
        let mut update_kbuckets_futures = Vec::new();
        for (topic_hash, topic_kbuckets) in kbuckets {
            update_kbuckets_futures.push(future::poll_fn(move |_cx| {
                if let Some(entry) = (*topic_kbuckets).take_applied_pending() {
                    let event = Discv5Event::NodeInsertedTopic {
                        node_id: entry.inserted.into_preimage(),
                        replaced: entry.evicted.map(|n| n.key.into_preimage()),
                        topic_hash: *topic_hash,
                    };
                    return Poll::Ready(event);
                }
                Poll::Pending
            }));
        }
        if update_kbuckets_futures.is_empty() {
            None
        } else {
            let (event, _, _) = select_all(update_kbuckets_futures).await;
            Some(event)
        }
    }

    /// A future the maintains active queries. This returns completed and timed out queries, as
    /// well as queries which need to be driven further with extra requests.
    async fn query_event_poll(queries: &mut QueryPool<QueryInfo, NodeId, Enr>) -> QueryEvent {
        future::poll_fn(move |_cx| match queries.poll() {
            QueryPoolState::Finished(query) => Poll::Ready(QueryEvent::Finished(Box::new(query))),
            QueryPoolState::Waiting(Some((query, return_peer))) => {
                let node_id = return_peer;
                let request_body = query.target().rpc_request(return_peer);
                Poll::Ready(QueryEvent::Waiting(
                    query.id(),
                    node_id,
                    Box::new(request_body),
                ))
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
    Waiting(QueryId, NodeId, Box<RequestBody>),
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
