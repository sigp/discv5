#[derive(Clone)]
pub struct FilterConfig {
    /// Whether the packet filter is enabled or not.
    pub enabled: bool,
    /// The maximum unsolicited requests per second. The average will be maintained such that packets will
    /// be rejected if above this rate.
    pub max_requests_per_second: usize,

    /// The maximum number of requests per NodeId per second. This must be less than
    /// `max_requests_per_second`.
    pub max_requests_per_node_per_second: Option<f64>,

    /// The maximum requests tolerated per IP per second. This must be less than
    /// `max_requests_per_second`.
    pub max_requests_per_ip_per_second: Option<f64>,
}

impl Default for FilterConfig {
    fn default() -> FilterConfig {
        FilterConfig {
            enabled: false,
            max_requests_per_second: 50,
            max_requests_per_node_per_second: Some(10.0),
            max_requests_per_ip_per_second: Some(10.0),
        }
    }
}
