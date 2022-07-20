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
    rpc, Discv5Config, Discv5Event, Enr, IpMode,
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
    collections::{hash_map::Entry, BTreeMap, HashMap},
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

/// The active and temporarily limited (too many tickets received from a node
/// in a given time span) registration attempts. Upon sending a REGTOPIC to
/// a node, it is inserted into RegAttempts with RegistrationState::Ticket.
#[derive(Default, Clone)]
pub struct RegAttempts {
    /// One registration attempt per node is allowed at a time.
    pub reg_attempts: HashMap<NodeId, RegistrationState>,
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
    /// Starts a topic look up of nodes advertising a topic in a discv5 network.
    TopicQuery(TopicHash, oneshot::Sender<Result<Vec<Enr>, RequestError>>),
    /// RegisterTopic publishes this node as an advertiser for a topic in a discv5 network
    /// until removed.
    RegisterTopic(TopicHash),
    /// Stops publishing this node as an advetiser for a topic.
    RemoveTopic(TopicHash, oneshot::Sender<Result<String, RequestError>>),
    /// Retrieves the ads currently published by this node on other nodes in a discv5 network.  
    ActiveTopics(oneshot::Sender<Result<HashMap<TopicHash, Vec<NodeId>>, RequestError>>),
    /// Retrieves the ads adveritsed for other nodes for a given topic.
    Ads(TopicHash, oneshot::Sender<Result<Vec<Enr>, RequestError>>),
    /// Retrieves the registration attempts acitve for a given topic.
    RegistrationAttempts(
        TopicHash,
        oneshot::Sender<Result<BTreeMap<u64, RegAttempts>, RequestError>>,
    ),
    /// Retrieves the node id of entries in a given topic's kbuckets by distance.
    TableEntriesIdTopic(
        TopicHash,
        oneshot::Sender<Result<BTreeMap<u64, Vec<NodeId>>, RequestError>>,
    ),
}

/// The max wait time accpeted for tickets.
const MAX_WAIT_TIME_TICKET: u64 = 60 * 5;

/// The time window within in which the number of new tickets from a peer for a topic will be limitied.
const TICKET_LIMITER_DURATION: Duration = Duration::from_secs(60 * 15);

/// The max nodes to adveritse for a topic.
const MAX_ADS_TOPIC: usize = 100;

/// The max nodes to advertise.
const MAX_ADS: usize = 50000;

/// The max ads per subnet per topic.
const MAX_ADS_SUBNET_TOPIC: usize = 5;

/// The max ads per subnet.
const MAX_ADS_SUBNET: usize = 50;

/// The time after a REGCONFIRMATION is sent that an ad is placed.
const AD_LIFETIME: Duration = Duration::from_secs(60 * 15);

/// The number of registration attempts that should be active per distance
/// if there are sufficient peers.
const MAX_REG_ATTEMPTS_DISTANCE: usize = 16;

/// Registration of topics are paced to occur at intervals t avoid a self-provoked DoS.
const REGISTER_INTERVAL: Duration = Duration::from_secs(60);

/// Registration attempts must be limited per registration interval.
const MAX_REGTOPICS_REGISTER_INTERVAL: usize = 16;

/// The max number of uncontacted peers to store before the kbuckets per topic.
const MAX_UNCONTACTED_PEERS_TOPIC_BUCKET: usize = 16;

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
    /// REGTOPIC request and REGCONFIRMATION that may be received if there is a free ad slot and
    /// the node is selected by the remote node for the free ad slot.
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

    /// Topics tracks registration attempts of the topic hashes to advertise on
    /// other nodes.
    registration_attempts: HashMap<TopicHash, BTreeMap<u64, RegAttempts>>,

    /// KBuckets per topic hash.
    topics_kbuckets: HashMap<TopicHash, KBucketsTable<NodeId, Enr>>,

    /// The peers returned in a NODES response to a TOPICQUERY or REGTOPIC request are inserted in
    /// this intermediary stroage to check their connectivity before inserting them in the topic's
    /// kbuckets.
    discovered_peers_topic: HashMap<TopicHash, BTreeMap<u64, HashMap<NodeId, Enr>>>,

    /// The key used for en-/decrypting tickets.
    ticket_key: [u8; 16],

    /// Tickets received by other nodes.
    tickets: Tickets,

    /// Locally issued tickets returned by nodes pending registration for free local ad slots.
    ticket_pools: TicketPools,

    /// Locally initiated topic query requests in process.
    active_topic_queries: ActiveTopicQueries,
}

/// The state of a topic lookup which changes as responses to sent TOPICQUERYs are received.
/// A topic look up may require more than one round of sending TOPICQUERYs to obtain the set
/// number of ads for the topic.
#[derive(Debug)]
pub enum TopicQueryState {
    /// The topic look up has obtained enough results.
    Finished(TopicHash),
    /// The topic look up has not obtained enough results and has timed out.
    TimedOut(TopicHash),
    /// Not enough ads have been returned from the first round of sending TOPICQUERY
    /// requests, new peers in the topic's kbucktes should be queried.
    Unsatisfied(TopicHash),
}

/// The state of a response to a single TOPICQUERY request. A topic lookup/query is
/// made up of several TOPICQUERYs each being sent to a different peer.
#[derive(Default)]
pub enum TopicQueryResponseState {
    /// The Start state is intermediary upon receving the first response to the
    /// TOPICQUERY request, either a NODES or ADNODES response.
    #[default]
    Start,
    /// A NODES response has been completely received.
    Nodes,
    /// An ADNODES response has been completely received.
    AdNodes,
}

/// At any given time, a set number of registrations should be active per topic hash to
/// set to be registered. A registration is active when either a ticket for an adslot is
/// held and the ticket wait time has not yet expired, or a REGCONFIRMATION has been
/// received for an ad slot and the ad lifetime has not yet elapsed.
#[derive(Debug, Clone)]
pub enum RegistrationState {
    /// A REGCONFIRMATION has been received at the given instant.
    Confirmed(Instant),
    /// A TICKET has been received and the ticket is being held for the duration of the
    /// wait time.
    Ticket,
    /// A fixed number of tickets are accepted within a certain time span. A node id in
    /// ticket limit regsitration state will not be sent a REGTOPIC till the ticket
    /// TICKET_LIMITER_DURATION has expired.
    TicketLimit(Instant),
}

/// An active topic query/lookup keeps track of which peers from the topic's kbuckets
/// have already been queired until the set number of ads are found for the lookup or it
/// is prematurely terminated in lack of peers or time.
pub struct ActiveTopicQuery {
    /// A NodeId mapped to false is waiting for a response. A value of true means the
    /// TOPICQUERY has received a response or the request has failed.
    queried_peers: HashMap<NodeId, bool>,
    /// An ad returned by multiple peers is only included once in the results.
    results: HashMap<NodeId, Enr>,
    /// The resulting ad nodes are returned to the app layer when the query has reached
    /// a Finished, TimedOut or Dry state.
    callback: Option<oneshot::Sender<Result<Vec<Enr>, RequestError>>>,
    /// A start time is used to montior time out of the query.
    start: Instant,
    /// A query is marked as dry being true if no peers are found in the topic's kbuckets
    /// that aren't already queried peers.
    dry: bool,
}

/// ActiveTopicQueries marks the progress of active topic queries/lookups.
pub struct ActiveTopicQueries {
    /// Each topic lookup initiates an ActiveTopicQuery process.
    queries: HashMap<TopicHash, ActiveTopicQuery>,
    /// The time out for any topic lookup.
    time_out: Duration,
    /// The number of ads an ActiveTopicQuery sets out to find.
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

impl Stream for ActiveTopicQueries {
    type Item = TopicQueryState;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        for (topic_hash, query) in self.queries.iter() {
            if query.dry {
                return Poll::Pending;
            } else if query.results.len() >= self.num_results {
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
                    return Poll::Ready(Some(TopicQueryState::Unsatisfied(*topic_hash)));
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

        let ads = match Ads::new(
            AD_LIFETIME,
            MAX_ADS_TOPIC,
            MAX_ADS,
            MAX_ADS_SUBNET,
            MAX_ADS_SUBNET_TOPIC,
        ) {
            Ok(ads) => ads,
            Err(e) => {
                return Err(Error::new(ErrorKind::InvalidInput, e));
            }
        };

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
                    registration_attempts: HashMap::new(),
                    topics_kbuckets: HashMap::new(),
                    discovered_peers_topic: HashMap::new(),
                    ticket_key: rand::random(),
                    tickets: Tickets::new(TICKET_LIMITER_DURATION),
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
        // In the case where not many peers populate the topic's kbuckets, ensure topics keep being republished.
        let mut registration_interval = tokio::time::interval(REGISTER_INTERVAL);
        let mut topics_to_reg_iter = self
            .registration_attempts
            .keys()
            .copied()
            .collect::<Vec<TopicHash>>()
            .into_iter();

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

                                trace!("Initiating kbuckets for topic hash {}", topic_hash);
                                let mut kbuckets = KBucketsTable::new(
                                    NodeId::new(&topic_hash.as_bytes()).into(),
                                    Duration::from_secs(60),
                                    self.config.incoming_bucket_limit,
                                    table_filter,
                                    bucket_filter,
                                );

                                debug!("Adding {} entries from local routing table to topic's kbuckets", self.kbuckets.write().iter().count());

                                for entry in self.kbuckets.write().iter() {
                                    match kbuckets.insert_or_update(entry.node.key, entry.node.value.clone(), entry.status) {
                                        InsertResult::Inserted
                                        | InsertResult::Pending { .. }
                                        | InsertResult::StatusUpdated { .. }
                                        | InsertResult::ValueUpdated
                                        | InsertResult::Updated { .. }
                                        | InsertResult::UpdatedPending => trace!(
                                            "Added node id {} to kbucket of topic hash {}",
                                            entry.node.value.node_id(),
                                            topic_hash
                                        ),
                                        InsertResult::Failed(f) => error!("Failed to insert ENR for topic hash {}. Failure reason: {:?}", topic_hash, f),
                                    }
                                }
                                self.topics_kbuckets.insert(topic_hash, kbuckets);
                            }
                            self.send_topic_queries(topic_hash, Some(callback));
                        }
                        ServiceRequest::RegisterTopic(topic_hash) => {
                            if self.registration_attempts.insert(topic_hash, BTreeMap::new()).is_some() {
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

                                trace!("Initiating kbuckets for topic hash {}", topic_hash);
                                let mut kbuckets = KBucketsTable::new(
                                    NodeId::new(&topic_hash.as_bytes()).into(),
                                    Duration::from_secs(60),
                                    self.config.incoming_bucket_limit,
                                    table_filter,
                                    bucket_filter,
                                );

                                debug!("Adding {} entries from local routing table to topic's kbuckets", self.kbuckets.write().iter().count());

                                for entry in self.kbuckets.write().iter() {
                                    match kbuckets.insert_or_update(entry.node.key, entry.node.value.clone(), entry.status) {
                                        InsertResult::Inserted
                                        | InsertResult::Pending { .. }
                                        | InsertResult::StatusUpdated { .. }
                                        | InsertResult::ValueUpdated
                                        | InsertResult::Updated { .. }
                                        | InsertResult::UpdatedPending => trace!(
                                            "Added node id {} to kbucket of topic hash {}",
                                            entry.node.value.node_id(),
                                            topic_hash
                                        ),
                                        InsertResult::Failed(f) => error!("Failed to insert ENR for topic hash {}. Failure reason: {:?}", topic_hash, f),
                                    }
                                }
                                self.topics_kbuckets.insert(topic_hash, kbuckets);
                                METRICS.topics_to_publish.store(self.registration_attempts.len(), Ordering::Relaxed);
                            }
                        }
                        ServiceRequest::ActiveTopics(callback) => {
                            let mut active_topics = HashMap::<TopicHash, Vec<NodeId>>::new();
                            self.registration_attempts.iter_mut().for_each(|(topic_hash, reg_attempts_by_distance)| {
                                for reg_attempts in reg_attempts_by_distance.values_mut() {
                                    reg_attempts.reg_attempts.retain(|node_id, reg_state| {
                                        match reg_state {
                                            RegistrationState::Confirmed(insert_time) => {
                                                if insert_time.elapsed() < AD_LIFETIME {
                                                    active_topics.entry(*topic_hash).or_default().push(*node_id);
                                                    true
                                                } else {
                                                    false
                                                }
                                            }
                                            RegistrationState::TicketLimit(insert_time) => insert_time.elapsed() < TICKET_LIMITER_DURATION,
                                            RegistrationState::Ticket => true,
                                        }
                                    });
                                }
                            });

                            if callback.send(Ok(active_topics)).is_err() {
                                error!("Failed to return active topics");
                            }
                        }
                        ServiceRequest::RemoveTopic(topic_hash, callback) => {
                            if self.registration_attempts.remove(&topic_hash).is_some() {
                                METRICS.topics_to_publish.store(self.registration_attempts.len(), Ordering::Relaxed);
                                if callback.send(Ok(base64::encode(topic_hash.as_bytes()))).is_err() {
                                    error!("Failed to return the removed topic {}", topic_hash);
                                }
                            }
                        }
                        ServiceRequest::Ads(topic_hash, callback) => {
                            let ads = self.ads.get_ad_nodes(topic_hash).map(|ad_node| ad_node.node_record().clone()).collect::<Vec<Enr>>();
                            if callback.send(Ok(ads)).is_err() {
                                error!("Failed to return ads for topic {}", topic_hash);
                            }
                        }
                        ServiceRequest::RegistrationAttempts(topic_hash, callback) => {
                            let reg_attempts = if let Some(reg_attempts) = self.registration_attempts.get(&topic_hash) {
                                reg_attempts.clone()
                            } else {
                                error!("Topic hash {} is not being registered", topic_hash);
                                BTreeMap::new()
                            };
                            if callback.send(Ok(reg_attempts)).is_err() {
                                error!("Failed to return registration attempts for topic hash {}", topic_hash);
                            }
                        }
                        ServiceRequest::TableEntriesIdTopic(topic_hash, callback) => {
                            let mut table_entries = BTreeMap::new();
                            if let Some(kbuckets) = self.topics_kbuckets.get_mut(&topic_hash) {
                                for (index, bucket) in kbuckets.buckets_iter().enumerate() {
                                    // The bucket's index in the Vec of buckets in the kbucket table will
                                    // be one less than the distance as the log2distance 0 from the local
                                    // node, i.e. the local node, is not assigned a bucket.
                                    let distance = index as u64 + 1;
                                    let mut node_ids = Vec::new();
                                    bucket.iter().for_each(|node| node_ids.push(*node.key.preimage()));
                                    table_entries.insert(distance, node_ids);
                                }
                            }
                            if callback.send(Ok(table_entries)).is_err() {
                                error!("Failed to return table entries' ids for topic hash {}", topic_hash);
                            }
                        }
                    }
                }
                Some(event) = self.handler_recv.recv() => {
                    match event {
                        HandlerOut::Established(enr, socket_addr, direction) => {
                            self.send_event(Discv5Event::SessionEstablished(enr.clone(), socket_addr));
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
                    // to the ticket issuer and the registration state for the given topic is
                    // updated.
                    if let Some(reg_attempts) = self.registration_attempts.get_mut(&active_topic.topic()) {
                        for kbucket_reg_attempts in reg_attempts.values_mut() {
                            let reg_state = kbucket_reg_attempts.reg_attempts.remove(active_topic.node_id());
                            if reg_state.is_some() {
                                break;
                            }
                        }
                    }
                    self.reg_topic_request(active_ticket.contact(), active_topic.topic(), enr, Some(active_ticket.ticket()));
                }
                Some(Ok((topic, mut ticket_pool))) = self.ticket_pools.next() => {
                    // Remove any tickets which don't have a current wait time of None.
                    ticket_pool.retain(|node_id, pool_ticket| self.ads.ticket_wait_time(topic, *node_id, *pool_ticket.ip()) == None);
                    // Select ticket with longest cummulative wait time.
                    if let Some(pool_ticket) = ticket_pool.values().max_by_key(|pool_ticket| pool_ticket.ticket().cum_wait()) {
                        let enr = pool_ticket.node_record();
                        let node_id = enr.node_id();
                        let _ = self.ads.insert(enr.clone(), topic).map_err(|e| error!("Couldn't insert ad from node id {} into ads. Error {}", node_id, e));
                        NodeContact::try_from_enr(enr.clone(), self.config.ip_mode).map(|contact| {
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
                        TopicQueryState::Unsatisfied(topic_hash) => {
                            self.send_topic_queries(topic_hash, None);
                        },
                    }
                }
                _ = registration_interval.tick() => {
                    let mut sent_regtopics = 0;
                    let mut topic_item = topics_to_reg_iter.next();
                    while let Some(topic_hash) = topic_item {
                        trace!("Republishing topic hash {}", topic_hash);
                        sent_regtopics += self.send_register_topics(topic_hash);
                        if sent_regtopics >= MAX_REGTOPICS_REGISTER_INTERVAL {
                            break
                        }
                        topic_item = topics_to_reg_iter.next();
                    }
                    if topic_item.is_none() {
                        topics_to_reg_iter = self.registration_attempts.keys().copied().collect::<Vec<TopicHash>>().into_iter();
                    }
                }
            }
        }
    }

    /// Internal function that starts a topic registration. This function should not be called outside of [`REGISTER_INTERVAL`].
    fn send_register_topics(&mut self, topic_hash: TopicHash) -> usize {
        trace!("Sending REGTOPICS");
        if let Entry::Occupied(ref mut kbuckets) = self.topics_kbuckets.entry(topic_hash) {
            trace!(
                "Found {} entries in kbuckets of topic hash {}",
                kbuckets.get_mut().iter().count(),
                topic_hash
            );
            let reg_attempts = self.registration_attempts.entry(topic_hash).or_default();
            let mut new_peers = Vec::new();

            // Ensure that max_reg_attempts_bucket registration attempts are alive per bucket if that many peers are
            // available at that distance.
            for (index, bucket) in kbuckets.get_mut().buckets_iter().enumerate() {
                if new_peers.len() >= MAX_REGTOPICS_REGISTER_INTERVAL {
                    break;
                }
                let distance = index as u64 + 1;
                let mut active_reg_attempts_bucket = 0;

                let registrations = reg_attempts.entry(distance).or_default();

                // Remove expired registrations and ticket limit blockages.
                registrations.reg_attempts.retain(|node_id, reg_state| {
                        trace!("Registration attempt of node id {}, reg state {:?} at distance {}", node_id, reg_state, distance);
                        match reg_state {
                            RegistrationState::Confirmed(insert_time) => {
                                if insert_time.elapsed() < AD_LIFETIME {
                                    active_reg_attempts_bucket += 1;
                                    true
                                } else {
                                    trace!("Registration has expired for node id {}. Removing from registration attempts.", node_id);
                                    false
                                }
                            }
                            RegistrationState::TicketLimit(insert_time) => insert_time.elapsed() < TICKET_LIMITER_DURATION,
                            RegistrationState::Ticket => {
                                active_reg_attempts_bucket += 1;
                                true
                            }
                        }
                    });

                let mut new_peers_bucket = Vec::new();

                // Attempt sending a request to uncontacted peers if any.
                if let Some(peers) = self.discovered_peers_topic.get_mut(&topic_hash) {
                    if let Some(bucket) = peers.get_mut(&distance) {
                        bucket.retain(|node_id, enr | {
                            if new_peers_bucket.len() + active_reg_attempts_bucket >= MAX_REG_ATTEMPTS_DISTANCE {
                                true
                            } else if let Entry::Vacant(_) = registrations.reg_attempts.entry(*node_id) {
                                debug!("Found new registration peer in uncontacted peers for topic {}. Peer: {:?}", topic_hash, node_id);
                                registrations.reg_attempts.insert(*node_id, RegistrationState::Ticket);
                                new_peers_bucket.push(enr.clone());
                                false
                            } else {
                                true
                            }
                        });
                        new_peers.append(&mut new_peers_bucket);
                    }
                }

                // The count of active registration attempts for a distance after expired ads have been
                // removed is less than the max number of registration attempts that should be active
                // per bucket and is not equal to the total number of peers available in that bucket.
                if active_reg_attempts_bucket < MAX_REG_ATTEMPTS_DISTANCE
                    && registrations.reg_attempts.len() != bucket.num_entries()
                {
                    for peer in bucket.iter() {
                        if new_peers_bucket.len() + active_reg_attempts_bucket
                            >= MAX_REG_ATTEMPTS_DISTANCE
                        {
                            break;
                        }
                        let node_id = *peer.key.preimage();
                        if let Entry::Vacant(_) = registrations.reg_attempts.entry(node_id) {
                            debug!(
                                "Found new registration peer in kbuckets of topic {}. Peer: {:?}",
                                topic_hash,
                                peer.key.preimage()
                            );
                            registrations
                                .reg_attempts
                                .insert(node_id, RegistrationState::Ticket);
                            new_peers_bucket.push(peer.value.clone())
                        }
                    }
                    new_peers.append(&mut new_peers_bucket);
                }
            }
            let mut sent_regtopics = 0;

            for peer in new_peers {
                let local_enr = self.local_enr.read().clone();
                if let Ok(node_contact) = NodeContact::try_from_enr(peer, self.config.ip_mode)
                    .map_err(|e| error!("Failed to send REGTOPIC to peer. Error: {:?}", e))
                {
                    self.reg_topic_request(node_contact, topic_hash, local_enr.clone(), None);
                    // If an uncontacted peer has a faulty enr, don't count the registration attempt.
                    sent_regtopics += 1;
                }
            }
            sent_regtopics
        } else {
            debug_unreachable!("Broken invariant, a kbuckets table should exist for topic hash");
            0
        }
    }

    /// Internal function that starts a topic lookup.
    fn send_topic_queries(
        &mut self,
        topic_hash: TopicHash,
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
                dry: false,
            });

        // Attempt to query max_topic_query_peers peers at a time. Possibly some peers will return more than one result
        // (ADNODES of length > 1), or no results will be returned from that peer.
        let max_topic_query_peers = self.config.max_nodes_response;

        let mut new_query_peers: Vec<Enr> = Vec::new();

        // Attempt sending a request to uncontacted peers if any.
        if let Some(peers) = self.discovered_peers_topic.get_mut(&topic_hash) {
            // Prefer querying nodes further away, i.e. in buckets of further distance to topic, to avoid hotspots.
            for bucket in peers.values_mut().rev() {
                if new_query_peers.len() < max_topic_query_peers {
                    break;
                }
                bucket.retain(|node_id, enr| {
                    if new_query_peers.len() >= max_topic_query_peers {
                        true
                    } else if let Entry::Vacant(entry) = query.queried_peers.entry(*node_id) {
                        entry.insert(false);
                        new_query_peers.push(enr.clone());
                        trace!(
                            "Found a new topic query peer {} in uncontacted peers of topic hash {}",
                            node_id,
                            topic_hash
                        );
                        false
                    } else {
                        true
                    }
                });
            }
        }

        if let Some(kbuckets) = self.topics_kbuckets.get_mut(&topic_hash) {
            // Prefer querying nodes further away, i.e. in buckets of further distance to topic, to avoid hotspots.
            for kbuckets_entry in kbuckets.iter().rev() {
                if new_query_peers.len() >= max_topic_query_peers {
                    break;
                }
                let node_id = *kbuckets_entry.node.key.preimage();
                let enr = kbuckets_entry.node.value;

                if let Entry::Vacant(entry) = query.queried_peers.entry(node_id) {
                    entry.insert(false);
                    new_query_peers.push(enr.clone());
                    trace!(
                        "Found a new topic query peer {} in kbuckets of topic hash {}",
                        node_id,
                        topic_hash
                    );
                }
            }
        }
        // If no new nodes can be found to query, let topic lookup wait for new peers or time out.
        if new_query_peers.is_empty() {
            debug!("Found no new peers to send TOPICQUERY to, setting query status to dry");
            if let Some(query) = self.active_topic_queries.queries.get_mut(&topic_hash) {
                query.dry = true;
            }
            return;
        }

        trace!("Sending TOPICQUERYs to {} new peers", new_query_peers.len());
        for enr in new_query_peers {
            if let Ok(node_contact) = NodeContact::try_from_enr(enr.clone(), self.config.ip_mode)
                .map_err(|e| error!("Failed to send TOPICQUERY to peer. Error: {:?}", e))
            {
                self.topic_query_request(node_contact, topic_hash);
            }
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
    pub fn find_enr(&mut self, node_id: &NodeId) -> Option<Enr> {
        // check if we know this node id in our routing table
        let key = kbucket::Key::from(*node_id);
        if let kbucket::Entry::Present(entry, _) = self.kbuckets.write().entry(&key) {
            return Some(entry.value().clone());
        }
        for kbuckets in self.topics_kbuckets.values_mut() {
            if let kbucket::Entry::Present(entry, _) = kbuckets.entry(&key) {
                return Some(entry.value().clone());
            }
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
            RequestBody::RegisterTopic { topic, enr, ticket } => {
                // Drop if request tries to advertise another node than sender
                if enr.node_id() != node_address.node_id {
                    debug!("The enr node id in REGTOPIC request body does not match sender's. Nodes can only register themselves.");
                    return;
                }
                match self.config.ip_mode {
                    IpMode::Ip4 => {
                        if enr.udp4_socket().map(SocketAddr::V4) != Some(node_address.socket_addr) {
                            debug!("The enr ip in REGTOPIC request body does not match sender's. Nodes can only register themselves.");
                            return;
                        }
                    }
                    IpMode::Ip6 { .. } => {
                        if enr.udp6_socket().map(SocketAddr::V6) != Some(node_address.socket_addr) {
                            debug!("The enr ip in REGTOPIC request body does not match sender's. Nodes can only register themselves.");
                            return;
                        }
                    }
                }
                self.send_find_topic_nodes_response(
                    topic,
                    node_address.clone(),
                    id.clone(),
                    "REGTOPIC",
                );

                // The current wait time for a given topic.
                let wait_time = self
                    .ads
                    .ticket_wait_time(topic, node_address.node_id, node_address.socket_addr.ip())
                    .unwrap_or(Duration::from_secs(0));

                let mut new_ticket = Ticket::new(
                    node_address.node_id,
                    node_address.socket_addr.ip(),
                    topic,
                    tokio::time::Instant::now(),
                    wait_time,
                    wait_time,
                );

                if !ticket.is_empty() {
                    let decrypted_ticket = {
                        let aead = Aes128Gcm::new(GenericArray::from_slice(&self.ticket_key));
                        let payload = Payload {
                            msg: &ticket,
                            aad: b"",
                        };
                        aead.decrypt(GenericArray::from_slice(&[1u8; 12]), payload)
                            .map_err(|e| {
                                error!("Failed to decrypt ticket in REGTOPIC request. Error: {}", e)
                            })
                    };
                    if let Ok(decrypted_ticket) = decrypted_ticket {
                        Ticket::decode(&decrypted_ticket)
                            .map_err(|e| {
                                error!("Failed to decode ticket in REGTOPIC request. Error: {}", e)
                            })
                            .map(|ticket| {
                                if let Some(ticket) = ticket {
                                    // A ticket is always be issued upon receiving a REGTOPIC request, even if there is no
                                    // wait time for the ad slot. See discv5 spec. This node will not store tickets received
                                    // with wait time 0.
                                    new_ticket.set_cum_wait(ticket.cum_wait());
                                    self.send_ticket_response(
                                        node_address.clone(),
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
                                            self.ticket_pools.insert(
                                                enr,
                                                id,
                                                ticket,
                                                node_address.socket_addr.ip(),
                                            );
                                        }
                                    }
                                }
                            })
                            .ok();
                    } else {
                        warn!("Node sent a ticket that couldn't be decrypted with local ticket key. Blacklisting: {}", node_address.node_id);
                        let ban_timeout = self.config.ban_duration.map(|v| Instant::now() + v);
                        PERMIT_BAN_LIST.write().ban(node_address, ban_timeout);
                        self.rpc_failure(id, RequestError::InvalidTicket);
                    }
                } else {
                    // A ticket is always be issued upon receiving a REGTOPIC request, even if there is no
                    // wait time for the ad slot. See discv5 spec. This node will not store tickets received
                    // with wait time 0.
                    self.send_ticket_response(
                        node_address.clone(),
                        id.clone(),
                        new_ticket.clone(),
                        wait_time,
                    );
                    // If current wait time is 0, the ticket is added to the matching ticket pool.
                    if wait_time == Duration::from_secs(0) {
                        self.ticket_pools.insert(
                            enr,
                            id,
                            new_ticket,
                            node_address.socket_addr.ip(),
                        );
                    }
                }
            }
            RequestBody::TopicQuery { topic } => {
                self.send_find_topic_nodes_response(
                    topic,
                    node_address.clone(),
                    id.clone(),
                    "TOPICQUERY",
                );
                trace!("Sending ADNODES response");
                self.send_topic_query_adnodes_response(node_address, id, topic);
            }
        }
    }

    /// Processes an RPC response from a peer.
    fn handle_rpc_response(&mut self, node_address: NodeAddress, response: Response) {
        // verify we know of the rpc_id
        let id = response.id.clone();

        let active_request = self
            .active_requests
            .remove(&id)
            .or_else(|| self.active_regtopic_requests.remove(&id));

        if let Some(mut active_request) = active_request {
            debug!(
                "Received RPC response: {} to request: {} from: {}",
                response.body, active_request.request_body, active_request.contact
            );

            // Check that the responder matches the expected request

            let expected_node_address = active_request.contact.node_address();
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
                    let distances_requested: Vec<u64> = match &active_request.request_body {
                        RequestBody::FindNode { distances } => distances.clone(),
                        RequestBody::TopicQuery { topic }
                        | RequestBody::RegisterTopic { topic, .. } => {
                            let peer_key: kbucket::Key<NodeId> = node_address.node_id.into();
                            let topic_key: kbucket::Key<NodeId> =
                                NodeId::new(&topic.as_bytes()).into();
                            let distance_to_topic = peer_key.log2_distance(&topic_key);
                            if let Some(distance) = distance_to_topic {
                                [distance - 1, distance, distance + 1].into()
                            } else {
                                warn!("The node id of this peer is the requested topic hash. Blacklisting peer with node id {}", node_id);
                                let ban_timeout =
                                    self.config.ban_duration.map(|v| Instant::now() + v);
                                PERMIT_BAN_LIST.write().ban(node_address, ban_timeout);
                                self.rpc_failure(id, RequestError::InvalidTicket);
                                return;
                            }
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

                    if let RequestBody::TopicQuery { topic } = active_request.request_body {
                        self.discovered(&node_id, nodes, active_request.query_id, Some(topic));

                        let response_state = self.topic_query_responses.entry(node_id).or_default();

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
                    } else if let RequestBody::RegisterTopic { topic, .. } =
                        active_request.request_body
                    {
                        self.discovered(&node_id, nodes, active_request.query_id, Some(topic));
                    } else if let RequestBody::FindNode { .. } = active_request.request_body {
                        self.discovered(&node_id, nodes, active_request.query_id, None)
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
                        nodes.retain(|enr| (self.config.table_filter)(enr));
                        if let Some(query) = self.active_topic_queries.queries.get_mut(&topic) {
                            nodes.into_iter().for_each(|enr| {
                                trace!(
                                    "Inserting node {} into query for topic hash {}",
                                    enr.node_id(),
                                    topic
                                );
                                query.results.insert(enr.node_id(), enr);
                            });
                            *query.queried_peers.entry(node_id).or_default() = true;
                        }
                        let response_state = self.topic_query_responses.entry(node_id).or_default();

                        match response_state {
                            TopicQueryResponseState::Start => {
                                *response_state = TopicQueryResponseState::AdNodes;
                                self.active_requests.insert(id, active_request);
                            }
                            TopicQueryResponseState::Nodes => {
                                trace!("TOPICQUERY has received expected responses");
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

                    // Only count votes that are from peers we have contacted.
                    let key: kbucket::Key<NodeId> = node_id.into();
                    let should_count = match self.kbuckets.write().entry(&key) {
                        kbucket::Entry::Present(_, status)
                            if status.is_connected() && !status.is_incoming() =>
                        {
                            true
                        }
                        _ => {
                            let mut should_count = false;
                            for kbuckets in self.topics_kbuckets.values_mut() {
                                match kbuckets.entry(&key) {
                                    kbucket::Entry::Present(_, status)
                                        if status.is_connected() && !status.is_incoming() =>
                                    {
                                        should_count = true;
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            should_count
                        }
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
                                    let new_ip6: SocketAddr = new_ip6.into();
                                    let result = self
                                        .local_enr
                                        .write()
                                        .set_udp_socket(new_ip6, &self.enr_key.read());
                                    match result {
                                        Ok(_) => {
                                            updated = true;
                                            info!("Local UDP ip6 socket updated to: {}", new_ip6);
                                            self.send_event(Discv5Event::SocketUpdated(new_ip6));
                                        }
                                        Err(e) => {
                                            warn!("Failed to update local UDP ip6 socket. ip6: {}, error: {:?}", new_ip6, e);
                                        }
                                    }
                                }
                                if let Some(new_ip4) = new_ip4 {
                                    let new_ip4: SocketAddr = new_ip4.into();
                                    let result = self
                                        .local_enr
                                        .write()
                                        .set_udp_socket(new_ip4, &self.enr_key.read());
                                    match result {
                                        Ok(_) => {
                                            updated = true;
                                            info!("Local UDP socket updated to: {}", new_ip4);
                                            self.send_event(Discv5Event::SocketUpdated(new_ip4));
                                        }
                                        Err(e) => {
                                            warn!("Failed to update local UDP socket. ip: {}, error: {:?}", new_ip4, e);
                                        }
                                    }
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
                        if let Err(e) = self.tickets.insert(
                            active_request.contact,
                            ticket,
                            Duration::from_secs(wait_time),
                            topic,
                        ) {
                            error!(
                                "Failed storing ticket from node id {}. Error {}",
                                node_id, e
                            );
                            if let Some(reg_attempts_by_distance) =
                                self.registration_attempts.get_mut(&topic)
                            {
                                let now = Instant::now();
                                let peer_key: kbucket::Key<NodeId> = node_id.into();
                                let topic_key: kbucket::Key<NodeId> =
                                    NodeId::new(&topic.as_bytes()).into();
                                if let Some(distance) = peer_key.log2_distance(&topic_key) {
                                    reg_attempts_by_distance.get_mut(&distance).map(|bucket| {
                                        bucket.reg_attempts.get_mut(&node_id).map(|reg_state| {
                                            *reg_state = RegistrationState::TicketLimit(now)
                                        })
                                    });
                                }
                            }
                        }
                    }
                }
                ResponseBody::RegisterConfirmation { topic } => {
                    let now = Instant::now();
                    let peer_key: kbucket::Key<NodeId> = node_id.into();
                    let topic_key: kbucket::Key<NodeId> = NodeId::new(&topic.as_bytes()).into();
                    if let Some(distance) = peer_key.log2_distance(&topic_key) {
                        let registration_attempts =
                            self.registration_attempts.entry(topic).or_default();
                        if let Some(reg_state) = registration_attempts
                            .entry(distance)
                            .or_default()
                            .reg_attempts
                            .get_mut(&node_id)
                        {
                            *reg_state = RegistrationState::Confirmed(now);
                        }

                        METRICS
                            .active_regtopic_req
                            .store(self.active_regtopic_requests.len(), Ordering::Relaxed);
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
        trace!("Sending reg topic to node {}", contact.socket_addr());
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
        let aead = Aes128Gcm::new(GenericArray::from_slice(&self.ticket_key));
        let payload = Payload {
            msg: &ticket.encode(),
            aad: b"",
        };
        let _ = aead
            .encrypt(GenericArray::from_slice(&[1u8; 12]), payload)
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
            });
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
        debug!(
            "Sending REGCONFIRMATION response to: {}. Response: {} ",
            node_address, response
        );
        let _ = self
            .handler_send
            .send(HandlerIn::Response(node_address, Box::new(response)));
    }

    /// Response to a topic query containing the nodes currently advertised for the
    /// requested topic if any.
    fn send_topic_query_adnodes_response(
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
        self.send_nodes_response(
            nodes_to_send,
            node_address,
            rpc_id,
            "TOPICQUERY",
            ResponseBody::AdNodes {
                total: 1u64,
                nodes: Vec::new(),
            },
        );
    }

    /// Finds a list of ENRs in the local routing table's kbucktets at the distance ±1 that
    /// the topic hash would be placed in, to send in a NODES response to a TOPICQUERY or
    /// REGTOPIC request.
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
                .for_each(|entry| {
                    if entry.node.key.preimage() != &node_address.node_id {
                        closest_peers.push(entry.node.value.clone())
                    }
                });

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
                    if entry.node.key.preimage() != &node_address.node_id {
                        closest_peers.push(entry.node.value.clone())
                    }
                }
            }
        }
        self.send_nodes_response(
            closest_peers,
            node_address,
            id,
            req_type,
            ResponseBody::Nodes {
                total: 1u64,
                nodes: Vec::new(),
            },
        );
    }

    /// Finds a list of ENRs in the local routing table at the given distances, to send in a
    /// NODES response to a FINDNODE request.
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
        self.send_nodes_response(
            nodes_to_send,
            node_address,
            rpc_id,
            "FINDNODE",
            ResponseBody::Nodes {
                total: 1u64,
                nodes: Vec::new(),
            },
        );
    }

    /// Sends a NODES response, given a list of ENRs. This function splits the nodes up
    /// into multiple responses to ensure the response stays below the maximum packet size.
    fn send_nodes_response(
        &self,
        nodes_to_send: Vec<Enr>,
        node_address: NodeAddress,
        rpc_id: RequestId,
        req_type: &str,
        resp_body: ResponseBody,
    ) {
        debug!("Sending NODES response to {} request {}", req_type, rpc_id);
        // if there are no nodes, send an empty response
        if nodes_to_send.is_empty() {
            let response = Response {
                id: rpc_id,
                body: resp_body.clone(),
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
                warn!(
                    "Failed to send empty response {} to request {} response. Error: {}",
                    resp_body, req_type, e
                )
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
                .map(|nodes| {
                    let body = match resp_body {
                        ResponseBody::AdNodes { .. } => ResponseBody::AdNodes {
                            total: (rpc_index + 1) as u64,
                            nodes,
                        },
                        _ => ResponseBody::Nodes {
                            total: (rpc_index + 1) as u64,
                            nodes,
                        },
                    };
                    Response {
                        id: rpc_id.clone(),
                        body,
                    }
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

    /// Processes discovered peers from a query or a TOPICQUERY or REGTOPIC request.
    fn discovered(
        &mut self,
        source: &NodeId,
        mut enrs: Vec<Enr>,
        query_id: Option<QueryId>,
        topic_hash: Option<TopicHash>,
    ) {
        let local_id = self.local_enr.read().node_id();

        enrs.retain(|enr| {
            if enr.node_id() == local_id {
                return false;
            }

            let mut new_or_updated_peer = false;

            // If any of the discovered nodes are in the routing table, and there contains an older ENR, update it.
            // If there is an event stream send the Discovered event
            if self.config.report_discovered_peers && topic_hash.is_none() {
                self.send_event(Discv5Event::Discovered(enr.clone()));
            }

            // ignore peers that don't pass the table filter
            if (self.config.table_filter)(enr) {
                let kbuckets_topic = topic_hash.and_then(|topic_hash| {
                    self.topics_kbuckets
                        .get_mut(&topic_hash)
                        .and_then(|kbuckets| {
                            Some(kbuckets).or_else(|| {
                                debug_unreachable!("A kbuckets table should exist for topic hash");
                                None
                            })
                        })
                });

                let key = kbucket::Key::from(enr.node_id());

                // If the ENR exists in the routing table and the discovered ENR has a greater
                // sequence number, perform some filter checks before updating the enr.

                if let Some(kbuckets_topic) = kbuckets_topic {
                    match kbuckets_topic.entry(&key) {
                        kbucket::Entry::Present(entry, _) => {
                            if entry.value().seq() < enr.seq() {
                                if let UpdateResult::Failed(reason) =
                                kbuckets_topic.update_node(&key, enr.clone(), None) {
                                    self.peers_to_ping.remove(&enr.node_id());
                                    debug!(
                                        "Failed to update discovered ENR for kbucket of topic hash {:?}. Node: {}, Reason: {:?}",
                                        topic_hash, source, reason
                                    );
                                    return false; // Remove this peer from the discovered list if the update failed
                                }
                                new_or_updated_peer = true;
                            }
                        },
                        kbucket::Entry::Pending(mut entry, _) => {
                            if entry.value().seq() < enr.seq() {
                                if let UpdateResult::Failed(reason) =
                                kbuckets_topic.update_node(&key, enr.clone(), None) {
                                    self.peers_to_ping.remove(&enr.node_id());
                                    debug!(
                                        "Failed to update discovered ENR for kbucket of topic hash {:?}. Node: {}, Reason: {:?}",
                                        topic_hash, source, reason
                                    );
                                    return false; // Remove this peer from the discovered list if the update failed
                                }
                                new_or_updated_peer = true;
                            }
                        }
                        kbucket::Entry::Absent(_) => {
                            if let Some(topic_hash) = topic_hash {
                                if self.config.report_discovered_peers {
                                    self.send_event(Discv5Event::DiscoveredNewPeerTopic(enr.clone(), topic_hash));
                                }
                                trace!("Discovered new peer {} for topic hash {}", enr.node_id(), topic_hash);
                                let discovered_peers =
                                    self.discovered_peers_topic.entry(topic_hash).or_default();
                                // If the intermediary storage before the topic's kbucktes is at bounds, discard the
                                // uncontacted peers.
                                let node_id = enr.node_id();
                                let peer_key: kbucket::Key<NodeId> = node_id.into();
                                let topic_key: kbucket::Key<NodeId> = NodeId::new(&topic_hash.as_bytes()).into();
                                if let Some(distance) = peer_key.log2_distance(&topic_key) {
                                    let bucket = discovered_peers.entry(distance).or_default();
                                    if bucket.len() < MAX_UNCONTACTED_PEERS_TOPIC_BUCKET {
                                        bucket.insert(node_id, enr.clone());
                                    } else {
                                        warn!("Discarding uncontacted peers, uncontacted peers at bounds for topic hash {}", topic_hash);
                                    }
                                }
                            }
                            new_or_updated_peer = true;
                        }
                        _ => {}
                    }
                } else {
                    let must_update_enr = match self.kbuckets.write().entry(&key) {
                        kbucket::Entry::Present(entry, _) => entry.value().seq() < enr.seq(),
                        kbucket::Entry::Pending(mut entry, _) => entry.value().seq() < enr.seq(),
                        _ => false,
                    };
                    if must_update_enr {
                    if let UpdateResult::Failed(reason) =
                        self.kbuckets.write().update_node(&key, enr.clone(), None) {
                            self.peers_to_ping.remove(&enr.node_id());
                            debug!(
                                "Failed to update discovered ENR. Node: {}, Reason: {:?}",
                                source, reason
                            );
                            return false; // Remove this peer from the discovered list if the update failed
                        }
                    }
                }
            } else {
                return false; // Didn't pass the table filter remove the peer
            }

            // The remaining ENRs are used if this request was part of a query. If we are
            // requesting the target of the query, this ENR could be the result of requesting the
            // target-nodes own id. We don't want to add this as a "new" discovered peer in the
            // query, so we remove it from the discovered list here.
            if topic_hash.is_some() {
                // For a topic lookup or registration only new or updated peers are retained.
                new_or_updated_peer && source != &enr.node_id()
            } else {
                source != &enr.node_id()
            }
        });

        if let Some(topic_hash) = topic_hash {
            if enrs.is_empty() {
                return;
            }
            // If a topic lookup has dried up (no more peers to query), the query can now proceed as long as
            // it hasn't timed out already.
            if let Some(query) = self.active_topic_queries.queries.get_mut(&topic_hash) {
                query.dry = false;
            }
            return;
        }

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
    /// the queue and newly added peers to the routing table (or topics kbucktes) are added to the queue.
    fn connection_updated(
        &mut self,
        node_id: NodeId,
        new_status: ConnectionStatus,
        topic_hash: Option<TopicHash>,
    ) {
        // Variables to that may require post-processing
        let mut ping_peer = None;
        let mut event_to_send = None;

        let kbuckets_topic = topic_hash.and_then(|topic_hash| {
            self.topics_kbuckets
                .get_mut(&topic_hash)
                .and_then(|kbuckets| {
                    Some(kbuckets).or_else(|| {
                        debug_unreachable!("A kbuckets table should exist for topic hash");
                        None
                    })
                })
        });

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

                if topic_hash.is_some() {
                    trace!(
                        "Inserting node into kbucket of topic gave result: {:?}",
                        insert_result
                    );
                }

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
                match self.kbuckets.write().update_node(
                    &key,
                    enr.clone(),
                    Some(ConnectionState::Connected),
                ) {
                    UpdateResult::Failed(FailureReason::KeyNonExistant) => {}
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
                for kbuckets in self.topics_kbuckets.values_mut() {
                    match kbuckets.update_node(&key, enr.clone(), Some(ConnectionState::Connected))
                    {
                        UpdateResult::Failed(FailureReason::KeyNonExistant) => {}
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
        if let Some(active_request) = self
            .active_requests
            .remove(&id)
            .or_else(|| self.active_regtopic_requests.remove(&id))
        {
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
                                None,
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
                    self.connection_updated(node_id, ConnectionStatus::Disconnected, Some(topic));
                    return;
                }
                RequestBody::RegisterTopic {
                    topic,
                    enr: _,
                    ticket: _,
                } => {
                    let peer_key: kbucket::Key<NodeId> = node_id.into();
                    let topic_key: kbucket::Key<NodeId> = NodeId::new(&topic.as_bytes()).into();
                    if let Some(distance) = peer_key.log2_distance(&topic_key) {
                        // Remove the registration attempt before disconnecting the peer.
                        let registration_attempts =
                            self.registration_attempts.entry(topic).or_default();
                        if let Some(bucket) = registration_attempts.get_mut(&distance) {
                            bucket.reg_attempts.remove(&node_id);
                        }

                        METRICS
                            .active_regtopic_req
                            .store(self.active_regtopic_requests.len(), Ordering::Relaxed);
                    }
                    self.connection_updated(node_id, ConnectionStatus::Disconnected, Some(topic));
                    return;
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

            self.connection_updated(node_id, ConnectionStatus::Disconnected, None);
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

    /// A future that maintains the topic kbuckets and inserts nodes when required. This optionally
    /// returns the `Discv5Event::NodeInsertedTopics` variant if a new node has been inserted into
    /// the routing table.
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
