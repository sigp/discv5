use std::net::IpAddr;

#[derive(Clone)]
pub struct FilterConfig {
    /// The maximum requests per second. The average will be maintained such that packets will
    /// be rejected if above this rate.
    pub max_requests_per_second: usize,

    /// The maximum number of requests per NodeId per second.
    pub max_requests_per_node_per_second: usize,

    /// The maximum requests tolerated per IP per second.
    pub max_requests_per_ip_per_second: usize,

    /// List of IP Addresses that bypass filter restrictions.
    pub white_listed_ips: Vec<IpAddr>,

    /// List of IP addresses that are banned and all packets will be dropped from.
    pub black_listed_ips: Vec<IpAddr>,
}

impl Default for FilterConfig {
    fn default() -> FilterConfig {
        FilterConfig {
            max_requests_per_second: 50,
            max_requests_per_node_per_second: 10,
            max_requests_per_ip_per_second: 10,
            white_listed_ips: Vec::new(),
            black_listed_ips: Vec::new(),
        }
    }
}
