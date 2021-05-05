//! Contains a collection of bucket filters use to restrict nodes from entering the routing
//! table.

/// Takes an `ENR` to insert and a list of other `ENR`s to compare against.
/// Returns `true` if `ENR` can be inserted and `false` otherwise.
/// `enr` can be inserted if the count of enrs in `others` in the same /24 subnet as `ENR`
/// is less than `limit`.
pub fn ip_filter(enr: &Enr, others: &[&Enr], limit: usize) -> bool {
    let mut allowed = true;
    if let Some(ip) = enr.ip() {
        let count = others.iter().flat_map(|e| e.ip()).fold(0, |acc, x| {
            if x.octets()[0..3] == ip.octets()[0..3] {
                acc + 1
            } else {
                acc
            }
        });
        if count >= limit {
            allowed = false;
        }
    };
    allowed
}

/// Checks the current bucket to ensure there is enough room to add another Incomming connected
/// peer.
pub fn direction_filter(bucket_nodes: &[&TableEntry], limit: usize) -> bool {
    let incoming_nodes = bucket_nodes
        .iter()
        .filter(|entry| entry.connection == NodeConnection::Incoming)
        .count();
    // Can add more incoming nodes if we are under the limit
    incoming_nodes < limit
}
