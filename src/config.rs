use crate::{
    ipmode::IpMode, kbucket::MAX_NODES_PER_BUCKET, Enr, Executor, PermitBanList, RateLimiter,
    RateLimiterBuilder,
};
///! A set of configuration parameters to tune the discovery protocol.
use std::time::Duration;

/// Configuration parameters that define the performance of the discovery network.
#[derive(Clone)]
pub struct Discv5Config {
    /// Whether to enable the incoming packet filter. Default: false.
    pub enable_packet_filter: bool,

    /// The request timeout for each UDP request. Default: 1 seconds.
    pub request_timeout: Duration,

    /// The interval over which votes are remembered when determining our external IP. A lower
    /// interval will respond faster to IP changes. Default is 30 seconds.
    pub vote_duration: Duration,

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

    /// The minimum number of peer's who tried to engage us in the NAT traversal protocol before
    /// updating the local ENR. Default: 10.
    pub enr_peer_update_min_nat: usize,

    /// The number of peers to request in parallel in a single query. Default: 3.
    pub query_parallelism: usize,

    /// Limits the number of IP addresses from the same
    /// /24 subnet in the kbuckets table. This is to mitigate eclipse attacks. Default: false.
    pub ip_limit: bool,

    /// When the NAT feature of Discv5 is enabled, this specifies the maximum number of nodes
    /// behind a symmetric NAT that are allowed per bucket. If set to None, no limit is applied.
    /// These peers are not passed around in NODES responses to other peers. By adding them to the
    /// kbuckets they can be sent requests which is useful for discovery queries. These nodes are
    /// identified by their ENR: their 'nat'/'nat6' field contains an ip but their 'udp' and 'udp6'
    /// fields are empty. The default value is to exclude these peers from the routing table. A
    /// reasonable default to include symmetric NAT'd peers is 2. Default: Some(0).
    pub nat_symmetric_limit: Option<usize>,

    /// Sets a maximum limit to the number of incoming nodes (nodes that have dialed us) to exist
    /// per-bucket. This cannot be larger than the bucket size (16). By default this is disabled
    /// (set to the maximum bucket size, 16).
    pub incoming_bucket_limit: usize,

    /// A filter used to decide whether to insert nodes into our local routing table. Nodes can be
    /// excluded if they do not pass this filter. The default is to accept all nodes.
    pub table_filter: fn(&Enr) -> bool,

    /// The time between pings to ensure connectivity amongst connected nodes. Default: 300
    /// seconds.
    pub ping_interval: Duration,

    /// Configures the type of socket to bind to. This also affects the selection of address to use
    /// to contact an ENR.
    pub ip_mode: IpMode,

    /// Reports all discovered ENRs when traversing the DHT to the event stream. Default true.
    pub report_discovered_peers: bool,

    /// A set of configuration parameters for setting inbound request rate limits. See
    /// [`RateLimiterBuilder`] for options. This is only functional if the packet filter is
    /// enabled via the `enable_packet_filter` option. See the `Default` implementation for
    /// default values. If set to None, inbound requests are not filtered.
    pub filter_rate_limiter: Option<RateLimiter>,

    /// The maximum number of node-ids allowed per IP address before the IP address gets banned.
    /// Having this set to None, disables this feature. Default value is 10. This is only
    /// applicable if the `enable_packet_filter` option is set.
    pub filter_max_nodes_per_ip: Option<usize>,

    /// The maximum number of nodes that can be banned by a single IP before that IP gets banned.
    /// The default is 5. This is only
    /// applicable if the `enable_packet_filter` option is set.
    pub filter_max_bans_per_ip: Option<usize>,

    /// A set of lists that permit or ban IP's or NodeIds from the server. See
    /// `crate::PermitBanList`.
    pub permit_ban_list: PermitBanList,

    /// Set the default duration for which nodes are banned for. This timeouts are checked every 5
    /// minutes, so the precision will be to the nearest 5 minutes. If set to `None`, bans from
    /// the filter will last indefinitely. Default is 1 hour.
    pub ban_duration: Option<Duration>,

    /// The max peers that contact us without an ENR with a reachable address that we store
    /// anticipating they find their externally reachable address (by ip voting) and set
    /// their ENR. The default is 100.
    pub max_awaiting_contactable_enr: usize,

    /// This node supports the NAT traversal protocol. Default is true.
    pub nat_feature: bool,

    /// The max number of relays to store per peer. All of these relays may be inactive for
    /// example if the peer hasn't successfully kept the holes in its NAT to its peers punched.
    /// Default is 10.
    pub max_relays_per_receiver: usize,

    /// The amount of time in seconds an inactive relay is stored before it can be replaced.
    /// Default is 15 minutes.
    pub inactive_relay_expiration: Duration,

    /// A custom executor which can spawn the discv5 tasks. This must be a tokio runtime, with
    /// timing support. By default, the executor that created the discv5 struct will be used.
    pub executor: Option<Box<dyn Executor + Send + Sync>>,
}

impl Default for Discv5Config {
    fn default() -> Self {
        // This is only applicable if enable_packet_filter is set.
        let filter_rate_limiter = Some(
            RateLimiterBuilder::new()
                .total_n_every(10, Duration::from_secs(1)) // Allow bursts, average 10 per second
                .node_n_every(8, Duration::from_secs(1)) // Allow bursts, average 8 per second
                .ip_n_every(9, Duration::from_secs(1)) // Allow bursts, average 9 per second
                .build()
                .expect("The total rate limit has been specified"),
        );

        Self {
            enable_packet_filter: false,
            request_timeout: Duration::from_secs(1),
            vote_duration: Duration::from_secs(30),
            query_peer_timeout: Duration::from_secs(2),
            query_timeout: Duration::from_secs(60),
            request_retries: 1,
            session_timeout: Duration::from_secs(86400),
            session_cache_capacity: 1000,
            enr_update: true,
            max_nodes_response: 16,
            enr_peer_update_min: 10,
            enr_peer_update_min_nat: 10,
            query_parallelism: 3,
            ip_limit: false,
            nat_symmetric_limit: Some(0),
            incoming_bucket_limit: MAX_NODES_PER_BUCKET,
            table_filter: |_| true,
            ping_interval: Duration::from_secs(300),
            report_discovered_peers: true,
            filter_rate_limiter,
            filter_max_nodes_per_ip: Some(10),
            filter_max_bans_per_ip: Some(5),
            permit_ban_list: PermitBanList::default(),
            ban_duration: Some(Duration::from_secs(3600)), // 1 hour
            ip_mode: IpMode::default(),
            max_awaiting_contactable_enr: 100,
            nat_feature: true,
            max_relays_per_receiver: 10,
            inactive_relay_expiration: Duration::from_secs(15 * 60),
            executor: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Discv5ConfigBuilder {
    config: Discv5Config,
}

impl Discv5ConfigBuilder {
    // set default values
    pub fn new() -> Self {
        Discv5ConfigBuilder::default()
    }

    /// Whether to enable the incoming packet filter.
    pub fn enable_packet_filter(&mut self) -> &mut Self {
        self.config.enable_packet_filter = true;
        self
    }

    /// The request timeout for each UDP request.
    pub fn request_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.request_timeout = timeout;
        self
    }

    /// The interval over which votes are remembered when determining our external IP. A lower
    /// interval will respond faster to IP changes. Default is 30 seconds.
    pub fn vote_duration(&mut self, vote_duration: Duration) -> &mut Self {
        self.config.vote_duration = vote_duration;
        self
    }

    /// The timeout after which a `QueryPeer` in an ongoing query is marked unresponsive.
    /// Unresponsive peers don't count towards the parallelism limits for a query.
    /// Hence, we may potentially end up making more requests to good peers.
    pub fn query_peer_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.query_peer_timeout = timeout;
        self
    }

    /// The timeout for an entire query. Any peers discovered before this timeout are returned.
    pub fn query_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.query_timeout = timeout;
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

    /// The minimum number of peer's who send RELAYREQUESTs before deciding wether to update the
    /// local ENR.
    pub fn enr_peer_update_min_nat(&mut self, min: usize) -> &mut Self {
        if min < 2 {
            panic!("Setting enr_peer_update_min_nat to a value less than 2 will cause issues with discovery with peers behind NAT");
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

    /// Limits the number of nodes behind a symmetric NAT per bucket when set to a value.
    /// Only makes sense to set if this node supports the NAT traversal protocol.
    pub fn symmetric_nat_limit(&mut self, limit_nat: Option<usize>) -> &mut Self {
        self.config.nat_symmetric_limit = limit_nat;
        self
    }

    /// Sets a maximum limit to the number of incoming nodes (nodes that have dialed us) to exist
    /// per-bucket. This cannot be larger than the bucket size (16). By default, half of every
    /// bucket (8 positions) is the largest number of nodes that we accept that dial us.
    pub fn incoming_bucket_limit(&mut self, limit: usize) -> &mut Self {
        self.config.incoming_bucket_limit = limit;
        self
    }

    /// A filter used to decide whether to insert nodes into our local routing table. Nodes can be
    /// excluded if they do not pass this filter.
    pub fn table_filter(&mut self, filter: fn(&Enr) -> bool) -> &mut Self {
        self.config.table_filter = filter;
        self
    }

    /// The time between pings to ensure connectivity amongst connected nodes. If this node
    /// is behind a NAT setting this will have no effect as the  node is required to ping its
    /// peers at a certain interval to ensure its NAT is hole punched.
    pub fn ping_interval(&mut self, interval: Duration) -> &mut Self {
        self.config.ping_interval = interval;
        self
    }

    /// Disables reporting of discovered peers through the event stream.
    pub fn disable_report_discovered_peers(&mut self) -> &mut Self {
        self.config.report_discovered_peers = false;
        self
    }

    /// A rate limiter for limiting inbound requests.
    pub fn filter_rate_limiter(&mut self, rate_limiter: Option<RateLimiter>) -> &mut Self {
        self.config.filter_rate_limiter = rate_limiter;
        self
    }

    /// If the filter is enabled, sets the maximum number of nodes per IP before banning
    /// the IP.
    pub fn filter_max_nodes_per_ip(&mut self, max_nodes_per_ip: Option<usize>) -> &mut Self {
        self.config.filter_max_nodes_per_ip = max_nodes_per_ip;
        self
    }

    /// The maximum number of times nodes from a single IP can be banned, before the IP itself
    /// gets banned.
    pub fn filter_max_bans_per_ip(&mut self, max_bans_per_ip: Option<usize>) -> &mut Self {
        self.config.filter_max_bans_per_ip = max_bans_per_ip;
        self
    }

    /// A set of lists that permit or ban IP's or NodeIds from the server. See
    /// `crate::PermitBanList`.
    pub fn permit_ban_list(&mut self, list: PermitBanList) -> &mut Self {
        self.config.permit_ban_list = list;
        self
    }

    /// Set the default duration for which nodes are banned for. This timeouts are checked every 5 minutes,
    /// so the precision will be to the nearest 5 minutes. If set to `None`, bans from the filter
    /// will last indefinitely. Default is 1 hour.
    pub fn ban_duration(&mut self, ban_duration: Option<Duration>) -> &mut Self {
        self.config.ban_duration = ban_duration;
        self
    }

    /// A custom executor which can spawn the discv5 tasks. This must be a tokio runtime, with
    /// timing support.
    pub fn executor(&mut self, executor: Box<dyn Executor + Send + Sync>) -> &mut Self {
        self.config.executor = Some(executor);
        self
    }

    /// Configures the type of socket to bind to. This also affects the selection of address to use
    /// to contact an ENR.
    pub fn ip_mode(&mut self, ip_mode: IpMode) -> &mut Self {
        self.config.ip_mode = ip_mode;
        self
    }

    pub fn max_awaiting_contactable_enr(&mut self, max_peers: usize) -> &mut Self {
        self.config.max_awaiting_contactable_enr = max_peers;
        self
    }

    /// Configures this node to run with or with out the NAT traversal protocol.
    pub fn nat_feature(&mut self, run_with_nat_feature: bool) -> &mut Self {
        self.config.nat_feature = run_with_nat_feature;
        self
    }

    /// Sets the max potential relays to store per peer.
    pub fn max_relays_per_receiver(&mut self, max_relays: usize) -> &mut Self {
        self.config.max_relays_per_receiver = max_relays;
        self
    }

    /// Sets the time to wait before allowing the replacement (by itself or another relay) of a
    /// relay which failed at relaying to a given peer.
    pub fn inactive_relay_expiration(&mut self, expiration_seconds: Duration) -> &mut Self {
        self.config.inactive_relay_expiration = expiration_seconds;
        self
    }

    pub fn build(&mut self) -> Discv5Config {
        // If an executor is not provided, assume a current tokio runtime is running.
        if self.config.executor.is_none() {
            self.config.executor = Some(Box::new(crate::executor::TokioExecutor::default()));
        };

        assert!(self.config.incoming_bucket_limit <= MAX_NODES_PER_BUCKET);

        self.config.clone()
    }
}

impl std::fmt::Debug for Discv5Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discv5Config")
            .field("filter_enabled", &self.enable_packet_filter)
            .field("request_timeout", &self.request_timeout)
            .field("vote_duration", &self.vote_duration)
            .field("query_peer_timeout", &self.query_peer_timeout)
            .field("query_timeout", &self.query_timeout)
            .field("request_retries", &self.request_retries)
            .field("session_timeout", &self.session_timeout)
            .field("session_cache_capacity", &self.session_cache_capacity)
            .field("enr_update", &self.enr_update)
            .field("max_nodes_response", &self.max_nodes_response)
            .field("enr_peer_update_min", &self.enr_peer_update_min)
            .field("enr_peer_update_min_nat", &self.enr_peer_update_min_nat)
            .field("query_parallelism", &self.query_parallelism)
            .field("ip_limit", &self.ip_limit)
            .field("nat_symmetric_limit", &self.nat_symmetric_limit)
            .field("incoming_bucket_limit", &self.incoming_bucket_limit)
            .field("ping_interval", &self.ping_interval)
            .field("ip_mode", &self.ip_mode)
            .field("report_discovered_peers", &self.report_discovered_peers)
            .field("filter_rate_limiter", &self.filter_rate_limiter)
            .field("filter_max_nodes_per_ip", &self.filter_max_nodes_per_ip)
            .field("filter_max_bans_per_ip", &self.filter_max_bans_per_ip)
            .field("permit_ban_list", &self.permit_ban_list)
            .field("ban_duration", &self.ban_duration)
            .field(
                "max_awaiting_contactable_enr",
                &self.max_awaiting_contactable_enr,
            )
            .field("nat_feature", &self.nat_feature)
            .field("max_relays_per_receiver", &self.max_relays_per_receiver)
            .field("inactive_relay_expiration", &self.inactive_relay_expiration)
            .finish()
    }
}
