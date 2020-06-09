use crate::node_info::NodeAddress;
use enr::NodeId;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct AllowDenyList {
    /// A set of IPs which pass all filters.
    pub allow_ips: HashSet<IpAddr>,
    /// A set of IPs whose packets get dropped instantly.
    pub deny_ips: HashSet<IpAddr>,
    /// A set of NodeIds which pass all filters.
    pub allow_nodes: HashSet<NodeId>,
    /// A set of NodeIds whose packets get dropped instantly.
    pub deny_nodes: HashSet<NodeId>,
}

impl Default for AllowDenyList {
    fn default() -> Self {
        AllowDenyList {
            allow_ips: HashSet::new(),
            deny_ips: HashSet::new(),
            allow_nodes: HashSet::new(),
            deny_nodes: HashSet::new(),
        }
    }
}

impl AllowDenyList {
    pub fn deny(&mut self, node_address: NodeAddress) {
        self.deny_ips.insert(node_address.socket_addr.ip());
        self.deny_nodes.insert(node_address.node_id);
    }
}
