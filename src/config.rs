use crate::{Enr, Executor, FilterConfig, PermitBanList};
///! A set of configuration parameters to tune the discovery protocol.
use std::time::Duration;

/// Configuration parameters that define the performance of the gossipsub network.
#[derive(Clone)]
pub struct Discv5Config {
    /// Whether to enable the incoming packet filter. Default: false.
    pub enable_packet_filter: bool,

    /// The request timeout for each UDP request. Default: 2 seconds.
    pub request_timeout: Duration,

    /// The timeout after which a `QueryPeer` in an ongoing query is marked unresponsive.
    /// Unresponsive peers don't count towards the parallelism limits for a query.
    /// Hence, we may potentially end up making more requests to good peers. Default: 2 seconds.
    pub query_peer_timeout: Duration,

    /// The timeout for an entire query. Any peers discovered for this query are returned. Default 60 seconds.
    pub query_timeout: Duration,

    /// The number of retries for each UDP request. Default: 1.
    pub request_retries: u8,

    /// The session timeout for each node. Default: 1 day.
    pub session_timeout: Duration,

    /// The maximum number of established sessions to maintain. Default: 1000.
    pub session_cache_capacity: usize,

    /// Updates the local ENR IP and port based on PONG responses from peers. Default: true.
    pub enr_update: bool,

    /// The maximum number of nodes we return to a find nodes request. The default is 16.
    pub max_nodes_response: usize,

    /// The minimum number of peer's who agree on an external IP port before updating the
    /// local ENR. Default: 10.
    pub enr_peer_update_min: usize,

    /// The number of peers to request in parallel in a single query. Default: 3.
    pub query_parallelism: usize,

    /// Limits the number of IP addresses from the same
    /// /24 subnet in the kbuckets table. This is to mitigate eclipse attacks. Default: false.
    pub ip_limit: bool,

    /// A filter used to decide whether to insert nodes into our local routing table. Nodes can be
    /// excluded if they do not pass this filter. The default is to accept all nodes.
    pub table_filter: fn(&Enr) -> bool,

    /// The callback for handling TALKREQ requests. The input to this callback is the protocol and
    /// the output is the response sent back to the requester.
    // This is a temporary measure and this may change in the future.
    pub talkreq_callback: fn(&[u8], &[u8]) -> Vec<u8>,

    /// The time between pings to ensure connectivity amongst connected nodes. Default: 300
    /// seconds.
    pub ping_interval: Duration,

    /// Reports all discovered ENR's when traversing the DHT to the event stream. Default true.
    pub report_discovered_peers: bool,

    /// A set of configuration parameters for the inbound packet filter. See `FilterConfig` for
    /// default values.
    pub filter_config: FilterConfig,

    /// A set of lists that permit or ban IP's or NodeIds from the server. See
    /// `crate::PermitBanList`.
    pub permit_ban_list: PermitBanList,

    /// A custom executor which can spawn the discv5 tasks. This must be a tokio runtime, with
    /// timing support. By default, the executor that created the discv5 struct will be used.
    pub executor: Option<Box<dyn Executor + Send + Sync>>,
}

impl Default for Discv5Config {
    fn default() -> Self {
        Self {
            enable_packet_filter: false,
            request_timeout: Duration::from_secs(1),
            query_peer_timeout: Duration::from_secs(2),
            query_timeout: Duration::from_secs(60),
            request_retries: 1,
            session_timeout: Duration::from_secs(86400),
            session_cache_capacity: 1000,
            enr_update: true,
            max_nodes_response: 16,
            enr_peer_update_min: 10,
            query_parallelism: 3,
            ip_limit: false,
            table_filter: |_| true,
            talkreq_callback: |_, _| Vec::new(),
            ping_interval: Duration::from_secs(300),
            report_discovered_peers: true,
            filter_config: FilterConfig::default(),
            permit_ban_list: PermitBanList::default(),
            executor: None,
        }
    }
}

#[derive(Debug)]
pub struct Discv5ConfigBuilder {
    config: Discv5Config,
}

impl Default for Discv5ConfigBuilder {
    fn default() -> Self {
        Self {
            config: Discv5Config::default(),
        }
    }
}

impl Discv5ConfigBuilder {
    // set default values
    pub fn new() -> Self {
        Discv5ConfigBuilder::default()
    }

    /// Whether to enable the incoming packet filter.
    pub fn enable_packet_filter(&mut self) -> &mut Self {
        self.config.filter_config.enabled = true;
        self.config.enable_packet_filter = true;
        self
    }

    /// The request timeout for each UDP request.
    pub fn request_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.request_timeout = timeout;
        self
    }

    /// The timeout for an entire query. Any peers discovered before this timeout are returned.
    pub fn query_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.query_timeout = timeout;
        self
    }

    /// The timeout after which a `QueryPeer` in an ongoing query is marked unresponsive.
    /// Unresponsive peers don't count towards the parallelism limits for a query.
    /// Hence, we may potentially end up making more requests to good peers.
    pub fn query_peer_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.query_peer_timeout = timeout;
        self
    }

    /// The number of retries for each UDP request.
    pub fn request_retries(&mut self, retries: u8) -> &mut Self {
        self.config.request_retries = retries;
        self
    }

    /// The session timeout for each node.
    pub fn session_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.session_timeout = timeout;
        self
    }

    /// The maximum number of established sessions to maintain.
    pub fn session_cache_capacity(&mut self, capacity: usize) -> &mut Self {
        self.config.session_cache_capacity = capacity;
        self
    }

    /// Disables the auto-update of the local ENR IP and port based on PONG responses from peers.
    pub fn disable_enr_update(&mut self) -> &mut Self {
        self.config.enr_update = false;
        self
    }

    /// The maximum number of nodes we response to a find nodes request.
    pub fn max_nodes_response(&mut self, max: usize) -> &mut Self {
        self.config.max_nodes_response = max;
        self
    }

    /// The minimum number of peer's who agree on an external IP port before updating the
    /// local ENR.
    pub fn enr_peer_update_min(&mut self, min: usize) -> &mut Self {
        if min < 2 {
            panic!("Setting enr_peer_update_min to a value less than 2 will cause issues with discovery with peers behind NAT");
        }
        self.config.enr_peer_update_min = min;
        self
    }

    /// The number of peers to request in parallel in a single query.
    pub fn query_parallelism(&mut self, parallelism: usize) -> &mut Self {
        self.config.query_parallelism = parallelism;
        self
    }

    /// Limits the number of IP addresses from the same
    /// /24 subnet in the kbuckets table. This is to mitigate eclipse attacks.
    pub fn ip_limit(&mut self) -> &mut Self {
        self.config.ip_limit = true;
        self
    }

    /// A filter used to decide whether to insert nodes into our local routing table. Nodes can be
    /// excluded if they do not pass this filter.
    pub fn table_filter(&mut self, filter: fn(&Enr) -> bool) -> &mut Self {
        self.config.table_filter = filter;
        self
    }

    /// The callback function for handling TALK requests. The input is the protocol in bytes and the request data in bytes and
    /// the output will be the response sent back to the requester.
    pub fn talkreq_callback(&mut self, callback: fn(&[u8], &[u8]) -> Vec<u8>) -> &mut Self {
        self.config.talkreq_callback = callback;
        self
    }

    /// The time between pings to ensure connectivity amongst connected nodes.
    pub fn ping_interval(&mut self, interval: Duration) -> &mut Self {
        self.config.ping_interval = interval;
        self
    }

    /// Disables reporting of discovered peers through the event stream.
    pub fn disable_report_discovered_peers(&mut self) -> &mut Self {
        self.config.report_discovered_peers = false;
        self
    }

    /// A set of configuration parameters for the inbound packet filter.
    pub fn filter_config(&mut self, config: FilterConfig) -> &mut Self {
        self.config.filter_config = config;
        self
    }

    /// A set of lists that permit or ban IP's or NodeIds from the server. See
    /// `crate::PermitBanList`.
    pub fn permit_ban_list(&mut self, list: PermitBanList) -> &mut Self {
        self.config.permit_ban_list = list;
        self
    }

    /// A custom executor which can spawn the discv5 tasks. This must be a tokio runtime, with
    /// timing support.
    pub fn executor(&mut self, executor: Box<dyn Executor + Send + Sync>) -> &mut Self {
        self.config.executor = Some(executor);
        self
    }

    pub fn build(&mut self) -> Discv5Config {
        // If an executor is not provided, assume a current tokio runtime is running.
        if self.config.executor.is_none() {
            self.config.executor = Some(Box::new(crate::executor::TokioExecutor::default()));
        };
        self.config.clone()
    }
}

impl std::fmt::Debug for Discv5Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = f.debug_struct("Discv5Config");
        let _ = builder.field("filter_enabled", &self.enable_packet_filter);
        let _ = builder.field("request_timeout", &self.request_timeout);
        let _ = builder.field("query_timeout", &self.query_timeout);
        let _ = builder.field("query_peer_timeout", &self.query_peer_timeout);
        let _ = builder.field("request_retries", &self.request_retries);
        let _ = builder.field("session_timeout", &self.session_timeout);
        let _ = builder.field("session_cache_capacity", &self.session_cache_capacity);
        let _ = builder.field("enr_update", &self.enr_update);
        let _ = builder.field("query_parallelism", &self.query_parallelism);
        let _ = builder.field("report_discovered_peers", &self.report_discovered_peers);
        let _ = builder.field("ip_limit", &self.ip_limit);
        let _ = builder.field("ping_interval", &self.ping_interval);
        builder.finish()
    }
}
