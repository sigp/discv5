///! A set of configuration parameters to tune the discovery protocol.
use std::time::Duration;

/// Configuration parameters that define the performance of the gossipsub network.
#[derive(Clone)]
pub struct Discv5Config {
    /// The request timeout for each UDP request. Default: 4 seconds.
    pub request_timeout: Duration,

    /// The timeout after which a `QueryPeer` in an ongoing query is marked unresponsive.
    /// Unresponsive peers don't count towards the parallelism limits for a query.
    /// Hence, we may potentially end up making more requests to good peers.
    pub query_peer_timeout: Duration,

    /// The timeout for an entire query.
    pub query_timeout: Duration,

    /// The number of retries for each UDP request. Default: 1.
    pub request_retries: u8,

    /// The session timeout for each node. Default: 1 day.
    //TODO: Make this a function of messages sent, to ensure nonce replay
    pub session_timeout: Duration,

    /// The timeout for a session to be established before being removed. Default: 15 seconds.
    pub session_establish_timeout: Duration,

    /// Updates the local ENR IP and port based on PONG responses from peers. Default: true.
    pub enr_update: bool,

    /// The minimum number of peer's who agree on an external IP port before updating the
    /// local ENR. Default: 10.
    pub enr_peer_update_min: usize,

    /// The number of peers to request in parallel in a single query. Default: 3.
    pub query_parallelism: usize,

    /// Limits the number of IP addresses from the same
    /// /24 subnet in the kbuckets table. This is to mitigate eclipse attacks. Default: false.
    pub ip_limit: bool,

    /// The time between pings to ensure connectivity amongst connected nodes. Duration: 300
    /// seconds.
    pub ping_interval: Duration,
}

impl Default for Discv5Config {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(4),
            query_peer_timeout: Duration::from_secs(2),
            query_timeout: Duration::from_secs(60),
            request_retries: 1,
            session_timeout: Duration::from_secs(86400),
            session_establish_timeout: Duration::from_secs(15),
            enr_update: true,
            enr_peer_update_min: 10,
            query_parallelism: 3,
            ip_limit: false,
            ping_interval: Duration::from_secs(300),
        }
    }
}

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

    pub fn request_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.request_timeout = timeout;
        self
    }

    pub fn query_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.query_timeout = timeout;
        self
    }

    pub fn query_peer_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.query_peer_timeout = timeout;
        self
    }

    pub fn request_retries(&mut self, retries: u8) -> &mut Self {
        self.config.request_retries = retries;
        self
    }

    pub fn session_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.session_timeout = timeout;
        self
    }

    pub fn session_establish_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.config.session_establish_timeout = timeout;
        self
    }

    pub fn enr_update(&mut self, update: bool) -> &mut Self {
        self.config.enr_update = update;
        self
    }

    pub fn enr_peer_update_min(&mut self, min: usize) -> &mut Self {
        if min < 2 {
            panic!("Setting enr_peer_update_min to a value less than 2 will cause issues with discovery with peers behind NAT");
        }
        self.config.enr_peer_update_min = min;
        self
    }

    pub fn query_parallelism(&mut self, parallelism: usize) -> &mut Self {
        self.config.query_parallelism = parallelism;
        self
    }

    pub fn ip_limit(&mut self, ip_limit: bool) -> &mut Self {
        self.config.ip_limit = ip_limit;
        self
    }

    pub fn ping_interval(&mut self, interval: Duration) -> &mut Self {
        self.config.ping_interval = interval;
        self
    }

    pub fn build(&self) -> Discv5Config {
        self.config.clone()
    }
}

impl std::fmt::Debug for Discv5Config {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut builder = f.debug_struct("Discv5Config");
        let _ = builder.field("request_timeout", &self.request_timeout);
        let _ = builder.field("query_timeout", &self.query_timeout);
        let _ = builder.field("query_peer_timeout", &self.query_peer_timeout);
        let _ = builder.field("request_retries", &self.request_retries);
        let _ = builder.field("session_timeout", &self.session_timeout);
        let _ = builder.field("session_establish_timeout", &self.session_establish_timeout);
        let _ = builder.field("enr_update", &self.enr_update);
        let _ = builder.field("query_parallelism", &self.query_parallelism);
        let _ = builder.field("ip_limit", &self.ip_limit);
        let _ = builder.field("ping_interval", &self.ping_interval);
        builder.finish()
    }
}
