//! Contains a collection of bucket filters use to restrict nodes from entering the routing
//! table.

use super::{Enr, NodeConnection, TableEntry};

/// Takes an `ENR` to insert and a list of other `ENR`s to compare against.
/// Returns `true` if `ENR` can be inserted and `false` otherwise.
/// `enr` can be inserted if the count of enrs in `others` in the same /24 subnet as `ENR`
/// is less than `limit`.
pub fn ip_filter<'a>(
    to_be_inserted: &Enr,
    others: impl Iterator<Item = &'a Enr>,
    limit: usize,
) -> bool {
    if let Some(ip) = to_be_inserted.ip() {
        let mut count = 0;
        for enr in others {
            if let Some(other_ip) = enr.ip() {
                if other_ip.octets()[0..3] == ip.octets()[0..3] {
                    count += 1;
                }
            }
            if count >= limit {
                return false;
            }
        }
    }
    true
}

/// Checks the current bucket to ensure there is enough room to add another Incomming connected
/// peer.
pub fn direction_filter<'a>(
    bucket_nodes: impl Iterator<Item = &'a TableEntry>,
    limit: usize,
) -> bool {
    let incoming_nodes = bucket_nodes
        .filter(|entry| entry.connection == NodeConnection::Incoming)
        .count();
    // Can add more incoming nodes if we are under the limit
    incoming_nodes < limit
}
