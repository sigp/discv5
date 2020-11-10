use crate::node_info::NodeAddress;
use enr::NodeId;
use std::{collections::HashSet, net::IpAddr};

#[derive(Debug, Clone)]
pub struct PermitBanList {
    /// A set of IPs which pass all filters.
    pub permit_ips: HashSet<IpAddr>,
    /// A set of IPs whose packets get dropped instantly.
    pub ban_ips: HashSet<IpAddr>,
    /// A set of NodeIds which pass all filters.
    pub permit_nodes: HashSet<NodeId>,
    /// A set of NodeIds whose packets get dropped instantly.
    pub ban_nodes: HashSet<NodeId>,
}

impl Default for PermitBanList {
    fn default() -> Self {
        PermitBanList {
            permit_ips: HashSet::new(),
            ban_ips: HashSet::new(),
            permit_nodes: HashSet::new(),
            ban_nodes: HashSet::new(),
        }
    }
}

impl PermitBanList {
    pub fn ban(&mut self, node_address: NodeAddress) {
        self.ban_ips.insert(node_address.socket_addr.ip());
        self.ban_nodes.insert(node_address.node_id);
    }
}
