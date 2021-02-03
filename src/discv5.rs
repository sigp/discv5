//! The Discovery v5 protocol. See the module level docs for further details.
//!
//! This provides the main struct for running and interfacing with a discovery v5 server.
//!
//! A [`Discv5`] struct needs to be created either with an [`Executor`] specified in the
//! [`Discv5Config`] via the [`Discv5ConfigBuilder`] or in the presence of a tokio runtime that has
//! timing and io enabled.
//!
//! Once a [`Discv5`] struct has been created the service is started by running the [`start()`]
//! functions with a UDP socket. This will start a discv5 server in the background listening on the
//! specified UDP socket.
//!
//! The server can be shutdown using the [`shutdown()`] function.

use crate::{
    error::{Discv5Error, QueryError, RequestError},
    kbucket::{self, ip_limiter, KBucketsTable, NodeStatus},
    node_info::NodeContact,
    service::{QueryKind, Service, ServiceRequest},
    Discv5Config, Enr,
};
use enr::{CombinedKey, EnrError, EnrKey, NodeId};
use parking_lot::RwLock;
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

#[cfg(feature = "libp2p")]
use {libp2p_core::Multiaddr, std::convert::TryFrom};

// Create lazy static variable for the global permit/ban list
use crate::metrics::{Metrics, METRICS};
lazy_static! {
    pub static ref PERMIT_BAN_LIST: RwLock<crate::PermitBanList> =
        RwLock::new(crate::PermitBanList::default());
}

mod test;

/// Events that can be produced by the `Discv5` event stream.
#[derive(Debug)]
pub enum Discv5Event {
    /// A node has been discovered from a FINDNODES request.
    ///
    /// The ENR of the node is returned. Various properties can be derived from the ENR.
    /// This happen spontaneously through queries as nodes return ENR's. These ENR's are not
    /// guaranteed to be live or contactable.
    Discovered(Enr),
    /// A new ENR was added to the routing table.
    EnrAdded { enr: Enr, replaced: Option<Enr> },
    /// A new node has been added to the routing table.
    NodeInserted {
        node_id: NodeId,
        replaced: Option<NodeId>,
    },
    /// Our local ENR IP address has been updated.
    SocketUpdated(SocketAddr),
}

/// The main Discv5 Service struct. This provides the user-level API for performing queries and
/// interacting with the underlying service.
pub struct Discv5 {
    config: Discv5Config,
    /// The channel to make requests from the main service.
    service_channel: Option<mpsc::Sender<ServiceRequest>>,
    /// The exit channel to shutdown the underlying service.
    service_exit: Option<oneshot::Sender<()>>,
    /// The routing table of the discv5 service.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Enr>>>,
    /// The local ENR of the server.
    local_enr: Arc<RwLock<Enr>>,
    /// The key associated with the local ENR, required for updating the local ENR.
    enr_key: Arc<RwLock<CombinedKey>>,
}

impl Discv5 {
    pub fn new(
        local_enr: Enr,
        enr_key: CombinedKey,
        mut config: Discv5Config,
    ) -> Result<Self, &'static str> {
        // ensure the keypair matches the one that signed the enr.
        if local_enr.public_key() != enr_key.public() {
            return Err("Provided keypair does not match the provided ENR");
        }

        // If an executor is not provided, assume a current tokio runtime is running. If not panic.
        if config.executor.is_none() {
            config.executor = Some(Box::new(crate::executor::TokioExecutor::default()));
        };

        let local_enr = Arc::new(RwLock::new(local_enr));
        let enr_key = Arc::new(RwLock::new(enr_key));
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            local_enr.read().node_id().into(),
            Duration::from_secs(60),
        )));

        // Update the PermitBan list based on initial configuration
        *PERMIT_BAN_LIST.write() = config.permit_ban_list.clone();

        Ok(Discv5 {
            config,
            service_channel: None,
            service_exit: None,
            kbuckets,
            local_enr,
            enr_key,
        })
    }

    /// Starts the required tasks and begins listening on a given UDP SocketAddr.
    pub async fn start(&mut self, listen_socket: SocketAddr) -> Result<(), Discv5Error> {
        if self.service_channel.is_some() {
            warn!("Service is already started");
            return Err(Discv5Error::ServiceAlreadyStarted);
        }

        // create the main service
        let (service_exit, service_channel) = Service::spawn(
            self.local_enr.clone(),
            self.enr_key.clone(),
            self.kbuckets.clone(),
            self.config.clone(),
            listen_socket,
        )
        .await?;
        self.service_exit = Some(service_exit);
        self.service_channel = Some(service_channel);
        Ok(())
    }

    /// Terminates the service.
    pub fn shutdown(&mut self) {
        if let Some(exit) = self.service_exit.take() {
            if exit.send(()).is_err() {
                debug!("Discv5 service already shutdown");
            }
            self.service_channel = None;
        } else {
            debug!("Service is already shutdown");
        }
    }

    /// Adds a known ENR of a peer participating in Service to the
    /// routing table.
    ///
    /// This allows pre-populating the Kademlia routing table with known
    /// addresses, so that they can be used immediately in following DHT
    /// operations involving one of these peers, without having to dial
    /// them upfront.
    pub fn add_enr(&mut self, enr: Enr) -> Result<(), &'static str> {
        // only add ENR's that have a valid udp socket.
        if enr.udp_socket().is_none() {
            warn!("ENR attempted to be added without a UDP socket has been ignored");
            return Err("ENR has no UDP socket to connect to");
        }

        if !(self.config.table_filter)(&enr) {
            warn!("ENR attempted to be added which is banned by the configuration table filter.");
            return Err("ENR banned by table filter");
        }

        let key = kbucket::Key::from(enr.node_id());

        // should the ENR be inserted or updated to a value that would exceed the IP limit ban
        let ip_limit_ban = self.config.ip_limit
            && !self
                .kbuckets
                .read()
                .check(&key, &enr, |v, o, l| ip_limiter(v, &o, l));

        match self.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(mut entry, _) => {
                // still update an ENR, regardless of the IP limit ban
                *entry.value() = enr;
            }
            kbucket::Entry::Pending(mut entry, _) => {
                *entry.value() = enr;
            }
            kbucket::Entry::Absent(entry) => {
                if !ip_limit_ban {
                    match entry.insert(enr, NodeStatus::Disconnected) {
                        kbucket::InsertResult::Inserted => {}
                        kbucket::InsertResult::Full => {
                            return Err("Table full");
                        }
                        kbucket::InsertResult::Pending { .. } => {}
                    }
                }
            }
            kbucket::Entry::SelfEntry => {}
        };
        Ok(())
    }

    /// Removes a `node_id` from the routing table.
    ///
    /// This allows applications, for whatever reason, to remove nodes from the local routing
    /// table. Returns `true` if the node was in the table and `false` otherwise.
    pub fn remove_node(&mut self, node_id: &NodeId) -> bool {
        let key = &kbucket::Key::from(*node_id);
        self.kbuckets.write().remove(key)
    }

    /// Mark a node in the routing table as `Disconnnected`.
    ///
    /// A `Disconnected` node will be present in the routing table and will be only
    /// used if there are no other `Connected` peers in the bucket.
    /// Returns `true` if node was in table and `false` otherwise.
    pub fn disconnect_node(&mut self, node_id: &NodeId) -> bool {
        let key = &kbucket::Key::from(*node_id);
        match self.kbuckets.write().entry(key) {
            kbucket::Entry::Present(entry, _) => {
                entry.update(NodeStatus::Disconnected);
                true
            }
            kbucket::Entry::Pending(entry, _) => {
                entry.update(NodeStatus::Disconnected);
                true
            }
            _ => false,
        }
    }

    /// Returns the number of connected peers that exist in the routing table.
    pub fn connected_peers(&self) -> usize {
        self.kbuckets
            .write()
            .iter()
            .filter(|entry| entry.status == NodeStatus::Connected)
            .count()
    }

    /// Gets the metrics associated with the Server
    pub fn metrics(&self) -> Metrics {
        Metrics::from(&METRICS)
    }

    /// Exposes the raw reference to the underlying internal metrics.
    pub fn raw_metrics() -> &'static METRICS {
        &METRICS
    }

    /// Returns the local ENR of the node.
    pub fn local_enr(&self) -> Enr {
        self.local_enr.read().clone()
    }

    /// Returns an ENR if one is known for the given NodeId.
    pub fn find_enr(&mut self, node_id: &NodeId) -> Option<Enr> {
        // check if we know this node id in our routing table
        let key = kbucket::Key::from(*node_id);
        if let kbucket::Entry::Present(mut entry, _) = self.kbuckets.write().entry(&key) {
            return Some(entry.value().clone());
        }
        None
    }

    /// Bans a node from the server. This will remove the node from the routing table if it exists
    /// and block all incoming packets from the node.
    pub fn ban_node(&mut self, node_id: &NodeId) {
        self.remove_node(node_id);
        PERMIT_BAN_LIST.write().ban_nodes.insert(*node_id);
    }

    /// Removes a banned node from the banned list.
    pub fn ban_node_remove(&mut self, node_id: &NodeId) {
        PERMIT_BAN_LIST.write().ban_nodes.remove(node_id);
    }

    /// Permits a node, allowing the node to bypass the packet filter.  
    pub fn permit_node(&mut self, node_id: &NodeId) {
        PERMIT_BAN_LIST.write().permit_nodes.insert(*node_id);
    }

    /// Removes a node from the permit list.
    pub fn permit_node_remove(&mut self, node_id: &NodeId) {
        PERMIT_BAN_LIST.write().permit_nodes.remove(node_id);
    }

    /// Bans an IP from the server.  This will block all incoming packets from the IP.
    pub fn ban_ip(&mut self, ip: std::net::IpAddr) {
        PERMIT_BAN_LIST.write().ban_ips.insert(ip);
    }

    /// Removes a banned IP from the banned list.
    pub fn ban_ip_remove(&mut self, ip: &std::net::IpAddr) {
        PERMIT_BAN_LIST.write().ban_ips.remove(ip);
    }

    /// Permits an IP, allowing the all packets from the IP to bypass the packet filter.  
    pub fn permit_ip(&mut self, ip: std::net::IpAddr) {
        PERMIT_BAN_LIST.write().permit_ips.insert(ip);
    }

    /// Removes an IP from the permit list.
    pub fn permit_ip_remove(&mut self, ip: &std::net::IpAddr) {
        PERMIT_BAN_LIST.write().permit_ips.remove(ip);
    }

    /// Updates the local ENR TCP/UDP socket.
    pub fn update_local_enr_socket(&mut self, socket_addr: SocketAddr, is_tcp: bool) -> bool {
        let local_socket = self.local_enr.read().udp_socket();
        if local_socket != Some(socket_addr) {
            if is_tcp {
                self.local_enr
                    .write()
                    .set_tcp_socket(socket_addr, &self.enr_key.read())
                    .is_ok()
            } else {
                self.local_enr
                    .write()
                    .set_udp_socket(socket_addr, &self.enr_key.read())
                    .is_ok()
            }
        } else {
            false
        }
    }

    /// Allows application layer to insert an arbitrary field into the local ENR.
    pub fn enr_insert(&mut self, key: &str, value: &[u8]) -> Result<Option<Vec<u8>>, EnrError> {
        self.local_enr
            .write()
            .insert(key, value, &self.enr_key.read())
            .map(|v| v.map(|v| v.to_vec()))
    }

    /// Returns an iterator over all ENR node IDs of nodes currently contained in the routing table.
    pub fn table_entries_id(&mut self) -> Vec<NodeId> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| *entry.node.key.preimage())
            .collect()
    }

    /// Returns an iterator over all the ENR's of nodes currently contained in the routing table.
    pub fn table_entries_enr(&mut self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| entry.node.value.clone())
            .collect()
    }

    /// Requests the ENR of a node corresponding to multiaddr or multi-addr string.
    ///
    /// Only `ed25519` and `secp256k1` key types are currently supported.
    ///
    /// Note: The async syntax is forgone here in order to create `'static` futures, where the
    /// underlying sending channel is cloned.
    #[cfg(feature = "libp2p")]
    #[cfg_attr(docsrs, doc(cfg(feature = "libp2p")))]
    pub fn request_enr(
        &mut self,
        multiaddr: impl std::convert::TryInto<Multiaddr> + 'static,
    ) -> impl Future<Output = Result<Enr, RequestError>> + 'static {
        let channel = self.clone_channel();

        async move {
            let channel = channel.map_err(|_| RequestError::ServiceNotStarted)?;
            // Sanitize the multiaddr

            // The multiaddr must support the udp protocol and be of an appropriate key type.
            // The conversion logic is contained in the `TryFrom<MultiAddr>` implementation of a
            // `NodeContact`.
            let multiaddr: Multiaddr = multiaddr.try_into().map_err(|_| {
                RequestError::InvalidMultiaddr("Could not convert to multiaddr".into())
            })?;
            let node_contact: NodeContact = NodeContact::try_from(multiaddr)
                .map_err(|e| RequestError::InvalidMultiaddr(e.into()))?;

            let (callback_send, callback_recv) = oneshot::channel();

            let event = ServiceRequest::FindEnr(node_contact, callback_send);
            channel
                .send(event)
                .await
                .map_err(|_| RequestError::ChannelFailed("Service channel closed".into()))?;
            callback_recv
                .await
                .map_err(|e| RequestError::ChannelFailed(e.to_string()))?
        }
    }

    /// Request a TALK message from a node, identified via the ENR.
    pub fn talk_req(
        &mut self,
        enr: Enr,
        protocol: Vec<u8>,
        request: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, RequestError>> + 'static {
        // convert the ENR to a node_contact.
        let node_contact = NodeContact::from(enr);

        // the service will verify if this node is contactable, we just send it and
        // await a response.
        let (callback_send, callback_recv) = oneshot::channel();
        let channel = self.clone_channel();

        async move {
            let channel = channel.map_err(|_| RequestError::ServiceNotStarted)?;

            let event = ServiceRequest::Talk(node_contact, protocol, request, callback_send);

            // send the request
            channel
                .send(event)
                .await
                .map_err(|_| RequestError::ChannelFailed("Service channel closed".into()))?;
            // await the response
            callback_recv
                .await
                .map_err(|e| RequestError::ChannelFailed(e.to_string()))?
        }
    }

    /// Runs an iterative `FIND_NODE` request.
    ///
    /// This will return peers containing contactable nodes of the DHT closest to the
    /// requested `NodeId`.
    ///
    /// Note: The async syntax is forgone here in order to create `'static` futures, where the
    /// underlying sending channel is cloned.
    pub fn find_node(
        &mut self,
        target_node: NodeId,
    ) -> impl Future<Output = Result<Vec<Enr>, QueryError>> + 'static {
        let channel = self.clone_channel();

        async move {
            let channel = channel.map_err(|_| QueryError::ServiceNotStarted)?;
            let (callback_send, callback_recv) = oneshot::channel();

            let query_kind = QueryKind::FindNode { target_node };

            let event = ServiceRequest::StartQuery(query_kind, callback_send);
            channel
                .send(event)
                .await
                .map_err(|_| QueryError::ChannelFailed("Service channel closed".into()))?;

            Ok(callback_recv
                .await
                .map_err(|e| QueryError::ChannelFailed(e.to_string()))?)
        }
    }

    /// Starts a `FIND_NODE` request.
    ///
    /// This will return less than or equal to `num_nodes` ENRs which satisfy the
    /// `predicate`.
    ///
    /// The predicate is a boxed function that takes an ENR reference and returns a boolean
    /// indicating if the record is applicable to the query or not.
    ///
    /// Note: The async syntax is forgone here in order to create `'static` futures, where the
    /// underlying sending channel is cloned.
    ///
    /// ### Example
    /// ```ignore
    ///  let predicate = Box::new(|enr: &Enr| enr.ip().is_some());
    ///  let target = NodeId::random();
    ///  let result = discv5.find_node_predicate(target, predicate, 5).await;
    ///  ```
    pub fn find_node_predicate(
        &mut self,
        target_node: NodeId,
        predicate: Box<dyn Fn(&Enr) -> bool + Send>,
        target_peer_no: usize,
    ) -> impl Future<Output = Result<Vec<Enr>, QueryError>> + 'static {
        let channel = self.clone_channel();

        async move {
            let channel = channel.map_err(|_| QueryError::ServiceNotStarted)?;
            let (callback_send, callback_recv) = oneshot::channel();

            let query_kind = QueryKind::Predicate {
                target_node,
                predicate,
                target_peer_no,
            };

            let event = ServiceRequest::StartQuery(query_kind, callback_send);
            channel
                .send(event)
                .await
                .map_err(|_| QueryError::ChannelFailed("Service channel closed".into()))?;

            Ok(callback_recv
                .await
                .map_err(|e| QueryError::ChannelFailed(e.to_string()))?)
        }
    }

    /// Creates an event stream channel which can be polled to receive Discv5 events.
    pub fn event_stream(
        &mut self,
    ) -> impl Future<Output = Result<mpsc::Receiver<Discv5Event>, Discv5Error>> + 'static {
        let channel = self.clone_channel();

        async move {
            let channel = channel?;

            let (callback_send, callback_recv) = oneshot::channel();

            let event = ServiceRequest::RequestEventStream(callback_send);
            channel
                .send(event)
                .await
                .map_err(|_| Discv5Error::ServiceChannelClosed)?;

            Ok(callback_recv
                .await
                .map_err(|_| Discv5Error::ServiceChannelClosed)?)
        }
    }

    /// Internal helper function to send events to the Service.
    fn clone_channel(&self) -> Result<mpsc::Sender<ServiceRequest>, Discv5Error> {
        if let Some(channel) = self.service_channel.as_ref() {
            Ok(channel.clone())
        } else {
            Err(Discv5Error::ServiceNotStarted)
        }
    }
}

impl Drop for Discv5 {
    fn drop(&mut self) {
        self.shutdown();
    }
}
