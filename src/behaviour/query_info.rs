use crate::kbucket::Key;
use crate::query_pool::ReturnPeer;
use crate::rpc::Request;
use enr::NodeId;
use enr::{CombinedKey, Enr};
use sha2::digest::generic_array::GenericArray;
use smallvec::SmallVec;

/// The number of distances to request when running a FINDNODE query. The probability that a peer returns
/// any given target peer is `1 - 0.5**MAX_FINDNODE_REQUESTS`.
const MAX_FINDNODE_REQUESTS: usize = 3;

/// Information about a query.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryInfo {
    /// What we are querying and why.
    pub query_type: QueryType,

    /// Temporary ENRs used when trying to reach nodes.
    pub untrusted_enrs: SmallVec<[Enr<CombinedKey>; 16]>,
}

/// Additional information about the query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryType {
    /// The user requested a `FIND_PEER` query to be performed. It should be reported when finished.
    FindNode(NodeId),
}

impl QueryInfo {
    /// Builds an RPC Request
    pub fn into_rpc_request(
        self,
        return_peer: &ReturnPeer<NodeId>,
    ) -> Result<Request, &'static str> {
        let request = match &self.query_type {
            QueryType::FindNode(node_id) => {
                let distance = findnode_log2distance(node_id, return_peer)
                    .ok_or_else(|| "Requested a node find itself")?;
                Request::FindNode { distance }
            }
        };

        Ok(request)
    }

    pub fn iterations(&self) -> usize {
        match &self.query_type {
            QueryType::FindNode(_) => MAX_FINDNODE_REQUESTS,
        }
    }
}

impl Into<Key<QueryInfo>> for QueryInfo {
    fn into(self) -> Key<QueryInfo> {
        let cloned_self = self.clone();
        match self.query_type {
            QueryType::FindNode(node_id) => {
                Key::new_raw(cloned_self, *GenericArray::from_slice(&node_id.raw()))
            }
        }
    }
}

/// Calculates the log2 distance for a destination peer given a target and current iteration.
///
/// As the iteration increases, FINDNODE requests adjacent distances from the exact peer distance.
///
/// As an example, if the target has a distance of 12 from the remote peer, the sequence of distances that are sent for increasing iterations would be [12, 13, 11, 14, 10, .. ].
fn findnode_log2distance(target: &NodeId, return_peer: &ReturnPeer<NodeId>) -> Option<u64> {
    let iteration = return_peer.iteration as u64;
    if iteration > 127 {
        // invoke and endless loop - coding error
        panic!("Iterations cannot be greater than 127");
    }

    let dst_key: Key<NodeId> = return_peer.node_id.clone().into();

    let distance = dst_key.log2_distance(&target.clone().into())?;

    let mut result_list = vec![distance];
    let mut difference = 1;
    while (result_list.len() as u64) < iteration {
        if distance + difference <= 256 {
            result_list.push(distance + difference);
        }
        if (result_list.len() as u64) < iteration {
            if let Some(d) = distance.checked_sub(difference) {
                result_list.push(d);
            }
        }
        difference += 1;
    }
    Some(result_list.pop().expect("List must have values"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2distance() {
        let target = NodeId::new(&[0u8; 32]);
        let mut destination = [0u8; 32];
        destination[10] = 1; // gives a log2 distance of 169
        let destination = NodeId::new(&destination);

        let expected_distances = vec![169, 170, 168, 171, 167, 172, 166, 173, 165];

        for (iteration, distance) in expected_distances.into_iter().enumerate() {
            let return_peer = ReturnPeer {
                node_id: destination.clone(),
                iteration: iteration + 1,
            };
            assert_eq!(
                findnode_log2distance(&target, &return_peer).unwrap(),
                distance
            );
        }
    }

    #[test]
    fn test_log2distance_lower() {
        let target = NodeId::new(&[0u8; 32]);
        let mut destination = [0u8; 32];
        destination[31] = 8; // gives a log2 distance of 5
        let destination = NodeId::new(&destination);

        let expected_distances = vec![4, 5, 3, 6, 2, 7, 1, 8, 0, 9, 10];

        for (iteration, distance) in expected_distances.into_iter().enumerate() {
            println!("{}", iteration);
            let return_peer = ReturnPeer {
                node_id: destination.clone(),
                iteration: iteration + 1,
            };
            assert_eq!(
                findnode_log2distance(&target, &return_peer).unwrap(),
                distance
            );
        }
    }

    #[test]
    fn test_log2distance_upper() {
        let target = NodeId::new(&[0u8; 32]);
        let mut destination = [0u8; 32];
        destination[0] = 8; // gives a log2 distance of 252
        let destination = NodeId::new(&destination);

        let expected_distances = vec![252, 253, 251, 254, 250, 255, 249, 256, 248, 247, 246];

        for (iteration, distance) in expected_distances.into_iter().enumerate() {
            let return_peer = ReturnPeer {
                node_id: destination.clone(),
                iteration: iteration + 1,
            };
            assert_eq!(
                findnode_log2distance(&target, &return_peer).unwrap(),
                distance
            );
        }
    }
}
