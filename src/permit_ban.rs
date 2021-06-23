use crate::node_info::NodeAddress;
use enr::NodeId;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Instant,
};

#[derive(Debug, Clone)]
pub struct PermitBanList {
    /// A set of IPs which pass all filters.
    pub permit_ips: HashSet<IpAddr>,
    /// A set of IPs whose packets get dropped instantly.
    pub ban_ips: HashMap<IpAddr, Option<Instant>>,
    /// A set of NodeIds which pass all filters.
    pub permit_nodes: HashSet<NodeId>,
    /// A set of NodeIds whose packets get dropped instantly.
    pub ban_nodes: HashMap<NodeId, Option<Instant>>,
}

impl Default for PermitBanList {
    fn default() -> Self {
        PermitBanList {
            permit_ips: HashSet::new(),
            ban_ips: HashMap::new(),
            permit_nodes: HashSet::new(),
            ban_nodes: HashMap::new(),
        }
    }
}

impl PermitBanList {
    pub fn ban(&mut self, node_address: NodeAddress, time_to_unban: Option<Instant>) {
        self.ban_ips
            .insert(node_address.socket_addr.ip(), time_to_unban);
        self.ban_nodes.insert(node_address.node_id, time_to_unban);
    }
}
