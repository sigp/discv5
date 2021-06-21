#[derive(Debug, Clone)]
pub struct FilterConfig {
    /// Whether the packet filter is enabled or not.
    pub enabled: bool,
    /// The maximum unsolicited requests per second. The average will be maintained such that packets will
    /// be rejected if above this rate. Responses to not add to this tally.
    pub max_requests_per_second: usize,
    /// The maximum number of requests per NodeId per second. This must be less than
    /// `max_requests_per_second`. This is an average of a 5 second moving window.
    pub max_requests_per_node_per_second: Option<f64>,
    /// The maximum requests tolerated per IP per second. This must be less than
    /// `max_requests_per_second`. This is an average of a 5 second moving window.
    pub max_requests_per_ip_per_second: Option<f64>,
    /// The maximum number of node-ids allowed per IP address before the IP address gets banned.
    /// Having this set to None, disables this feature. Default value is 10.
    pub max_nodes_per_ip: Option<usize>,
    /// The maximum number of nodes that can be banned by a single IP before that IP gets banned.
    /// The default is 5.
    pub max_bans_per_ip: Option<usize>,
}

impl Default for FilterConfig {
    fn default() -> FilterConfig {
        FilterConfig {
            enabled: false,
            max_requests_per_second: 10,
            max_requests_per_node_per_second: Some(8.0),
            max_requests_per_ip_per_second: Some(8.0),
            max_nodes_per_ip: Some(10),
            max_bans_per_ip: Some(5),
        }
    }
}

#[derive(Debug)]
pub struct FilterConfigBuilder {
    config: FilterConfig,
}

impl Default for FilterConfigBuilder {
    fn default() -> Self {
        Self {
            config: FilterConfig::default(),
        }
    }
}

impl FilterConfigBuilder {
    /// Enable the packet filter
    pub fn enable(&mut self) -> &mut Self {
        self.config.enabled = true;
        self
    }

    /// Set the maximum unsolicited requests per second.
    pub fn max_requests_per_second(&mut self, reqs_per_second: usize) -> &mut Self {
        self.config.max_requests_per_second = reqs_per_second;
        self
    }

    /// Sets the maximum unsolicited requests per node per second.
    pub fn max_requests_per_node_per_second(&mut self, reqs_per_node_per_second: f64) -> &mut Self {
        self.config.max_requests_per_node_per_second = Some(reqs_per_node_per_second);
        self
    }

    /// Sets the maximum unsolicited requests per ip per second.
    pub fn max_requests_per_ip_per_second(&mut self, reqs_per_ip_per_second: f64) -> &mut Self {
        self.config.max_requests_per_ip_per_second = Some(reqs_per_ip_per_second);
        self
    }

    pub fn build(&self) -> FilterConfig {
        assert!(
            self.config.max_requests_per_node_per_second.unwrap_or(0.0)
                < self.config.max_requests_per_second as f64,
            "Max requests per node must be less than max requests per second"
        );
        assert!(
            self.config.max_requests_per_ip_per_second.unwrap_or(0.0)
                < self.config.max_requests_per_second as f64,
            "Max requests per ip must be less than max requests per second"
        );
        self.config.clone()
    }
}
