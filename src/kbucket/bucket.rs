// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

// This basis of this file has been taken from the rust-libp2p codebase:
// https://github.com/libp2p/rust-libp2p

//! The internal API for a single `KBucket` in a `KBucketsTable`.
//!
//! > **Note**: Uniqueness of entries w.r.t. a `Key` in a `KBucket` is not
//! > checked in this module. This is an invariant that must hold across all
//! > buckets in a `KBucketsTable` and hence is enforced by the public API
//! > of the `KBucketsTable` and in particular the public `Entry` API.

#![allow(dead_code)]

use super::*;

/// Maximum number of nodes in a bucket, i.e. the (fixed) `k` parameter.
pub const MAX_NODES_PER_BUCKET: usize = 16;

/// A `PendingNode` is a `Node` that is pending insertion into a `KBucket`.
#[derive(Debug, Clone)]
pub struct PendingNode<TNodeId, TVal> {
    /// The pending node to insert.
    node: Node<TNodeId, TVal>,

    /// The instant at which the pending node is eligible for insertion into a bucket.
    replace: Instant,
}

/// The status of a node in a bucket.
///
/// The status of a node in a bucket together with the time of the
/// last status change determines the position of the node in a
/// bucket.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum NodeStatus {
    /// The node is considered connected via an incoming negotiation.
    ConnectedIncoming,
    /// The node is considered connected via an outgoing negotiation.
    ConnectedOutgoing,
    /// The node is considered disconnected.
    Disconnected,
}

impl NodeStatus {
    fn is_connected(&self) -> bool {
        match self {
            NodeStatus::Disconnected => false,
            _ => true,
        }
    }
}

impl<TNodeId, TVal> PendingNode<TNodeId, TVal> {
    pub fn status(&self) -> NodeStatus {
        self.node.status
    }

    pub fn value_mut(&mut self) -> &mut TVal {
        &mut self.node.value
    }

    pub fn set_ready_at(&mut self, t: Instant) {
        self.replace = t;
    }
}

/// A `Node` in a bucket, representing a peer participating
/// in the Kademlia DHT together with an associated value (e.g. contact
/// information).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node<TNodeId, TVal> {
    /// The key of the node, identifying the peer.
    pub key: Key<TNodeId>,
    /// The associated value.
    pub value: TVal,
    /// The status of the node.
    pub status: NodeStatus,
}

impl<TNodeId, TVal> Node<TNodeId, TVal> {
    fn is_connected(&self) -> bool {
        match self.status {
            NodeStatus::ConnectedOutgoing | NodeStatus::ConnectedIncoming => true,
            NodeStatus::Disconnected => false,
        }
    }
}

/// The position of a node in a `KBucket`, i.e. a non-negative integer
/// in the range `[0, MAX_NODES_PER_BUCKET)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position(usize);

/// A `KBucket` is a list of up to `MAX_NODES_PER_BUCKET` `Key`s and associated values,
/// ordered from least-recently connected to most-recently connected.
#[derive(Clone)]
pub struct KBucket<TNodeId, TVal> {
    /// The nodes contained in the bucket.
    nodes: ArrayVec<Node<TNodeId, TVal>, MAX_NODES_PER_BUCKET>,

    /// The position (index) in `nodes` that marks the first connected node.
    ///
    /// Since the entries in `nodes` are ordered from least-recently connected to
    /// most-recently connected, all entries above this index are also considered
    /// connected, i.e. the range `[0, first_connected_pos)` marks the sub-list of entries
    /// that are considered disconnected and the range
    /// `[first_connected_pos, MAX_NODES_PER_BUCKET)` marks sub-list of entries that are
    /// considered connected.
    ///
    /// `None` indicates that there are no connected entries in the bucket, i.e.
    /// the bucket is either empty, or contains only entries for peers that are
    /// considered disconnected.
    first_connected_pos: Option<usize>,

    /// A node that is pending to be inserted into a full bucket, should the
    /// least-recently connected (and currently disconnected) node not be
    /// marked as connected within `unresponsive_timeout`.
    pending: Option<PendingNode<TNodeId, TVal>>,

    /// The timeout window before a new pending node is eligible for insertion,
    /// if the least-recently connected node is not updated as being connected
    /// in the meantime.
    pending_timeout: Duration,

    /// An optional filter that filters new entries given an iterator over current entries in
    /// the bucket.
    filter: Option<Box<dyn Filter<TVal>>>,

    /// The maximum number of incoming connections allowed per bucket. Setting this to
    /// MAX_NODES_PER_BUCKET means there is no restriction on incoming nodes.
    max_incoming: usize,
}

/// The result of inserting an entry into a bucket.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertResult<TNodeId> {
    /// The entry has been successfully inserted.
    Inserted,
    /// The entry is pending insertion because the relevant bucket is currently full.
    /// The entry is inserted after a timeout elapsed, if the status of the
    /// least-recently connected (and currently disconnected) node in the bucket
    /// is not updated before the timeout expires.
    Pending {
        /// The key of the least-recently connected entry that is currently considered
        /// disconnected and whose corresponding peer should be checked for connectivity
        /// in order to prevent it from being evicted. If connectivity to the peer is
        /// re-established, the corresponding entry should be updated with
        /// [`NodeStatus::Connected`].
        disconnected: Key<TNodeId>,
    },
    /// The attempted entry failed to pass the filter.
    FailedFilter,
    /// There were too many incoming nodes for this bucket.
    TooManyIncoming,
    /// The entry was not inserted because the relevant bucket is full.
    Full,
    /// The entry already exists.
    NodeExists,
}

/// The result of performing an update on a kbucket/table.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateResult {
    /// The node was updated successfully,
    Updated,
    /// The update promoted the node to a connected state from a disconnected state.
    UpdatedAndPromoted,
    /// The pending entry was updated.
    UpdatedPending,
    /// The update removed the node because it would violate the incoming peers condition.
    UpdateFailed(FailureReason),
    /// There were no changes made to the value of the node.
    NotModified,
}

impl UpdateResult {
    // The update failed.
    pub fn failed(&self) -> bool {
        match self {
            UpdateResult::UpdateFailed(_) => true,
            _ => false,
        }
    }
}

/// A reason for failing to update or insert a node into the bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    /// Too many incoming nodes already in the bucket.
    TooManyIncoming,
    /// The node didn't pass the bucket filter.
    BucketFilter,
    /// The node didn't pass the table filter.
    TableFilter,
    /// The node didn't exist.
    KeyNonExistant,
    /// The bucket was full.
    BucketFull,
    /// Cannot update self,
    InvalidSelfUpdate,
}

/// The result of applying a pending node to a bucket, possibly
/// replacing an existing node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPending<TNodeId, TVal> {
    /// The key of the inserted pending node.
    pub inserted: Key<TNodeId>,
    /// The node that has been evicted from the bucket to make room for the
    /// pending node, if any.
    pub evicted: Option<Node<TNodeId, TVal>>,
}

impl<TNodeId, TVal> KBucket<TNodeId, TVal>
where
    TNodeId: Clone,
    TVal: Eq,
{
    /// Creates a new `KBucket` with the given timeout for pending entries.
    pub fn new(
        pending_timeout: Duration,
        max_incoming: usize,
        filter: Option<Box<dyn Filter<TVal>>>,
    ) -> Self {
        KBucket {
            nodes: ArrayVec::new(),
            first_connected_pos: None,
            pending: None,
            pending_timeout,
            filter,
            max_incoming,
        }
    }

    /// Returns a reference to the pending node of the bucket, if there is any.
    pub fn pending(&self) -> Option<&PendingNode<TNodeId, TVal>> {
        self.pending.as_ref()
    }

    /// Returns a mutable reference to the pending node of the bucket, if there is any.
    pub fn pending_mut(&mut self) -> Option<&mut PendingNode<TNodeId, TVal>> {
        self.pending.as_mut()
    }

    /// Returns a reference to the pending node of the bucket, if there is any
    /// with a matching key.
    pub fn as_pending(&self, key: &Key<TNodeId>) -> Option<&PendingNode<TNodeId, TVal>> {
        self.pending().filter(|p| &p.node.key == key)
    }

    /// Returns an iterator over the nodes in the bucket, together with their status.
    pub fn iter(&self) -> impl Iterator<Item = &Node<TNodeId, TVal>> {
        self.nodes.iter()
    }

    /// Inserts the pending node into the bucket, if its timeout has elapsed,
    /// replacing the least-recently connected node.
    ///
    /// If a pending node has been inserted, its key is returned together with
    /// the node that was replaced. `None` indicates that the nodes in the
    /// bucket remained unchanged.
    pub fn apply_pending(&mut self) -> Option<AppliedPending<TNodeId, TVal>> {
        if let Some(pending) = self.pending.take() {
            if pending.replace <= Instant::now() {
                if self.nodes.is_full() {
                    // Apply bucket filters

                    // Check if the bucket is full
                    if self.nodes[0].is_connected() {
                        // The bucket is full with connected nodes. Drop the pending node.
                        return None;
                    }
                    // Check the custom filter
                    if let Some(filter) = self.filter {
                        if !filter.filter(
                            &pending.node.value,
                            self.iter().map(|(node, _)| &node.value),
                        ) {
                            return None;
                        }
                    }
                    // Check the incoming node restriction
                    if let NodeStatus::ConnectedIncoming = pending.status() {
                        // Make sure this doesn't violate the incoming conditions
                        if self.is_max_incoming() {
                            return None;
                        }
                    }

                    // The pending node will be inserted.
                    let inserted = pending.node.key.clone();
                    // A connected pending node goes at the end of the list for
                    // the connected peers, removing the least-recently connected.
                    if pending.status().is_connected() {
                        let evicted = Some(self.nodes.remove(0));
                        self.first_connected_pos = self
                            .first_connected_pos
                            .map_or_else(|| Some(self.nodes.len()), |p| p.checked_sub(1));
                        self.nodes.push(pending.node);
                        return Some(AppliedPending { inserted, evicted });
                    }
                    // A disconnected pending node goes at the end of the list
                    // for the disconnected peers.
                    else if let Some(p) = self.first_connected_pos {
                        if let Some(insert_pos) = p.checked_sub(1) {
                            let evicted = Some(self.nodes.remove(0));
                            self.nodes.insert(insert_pos, pending.node);
                            return Some(AppliedPending { inserted, evicted });
                        }
                    } else {
                        // All nodes are disconnected. Insert the new node as the most
                        // recently disconnected, removing the least-recently disconnected.
                        let evicted = Some(self.nodes.remove(0));
                        self.nodes.push(pending.node);
                        return Some(AppliedPending { inserted, evicted });
                    }
                } else {
                    // There is room in the bucket, so just insert the pending node.
                    let inserted = pending.node.key.clone();
                    match self.insert(pending.node) {
                        InsertResult::Inserted => {
                            return Some(AppliedPending {
                                inserted,
                                evicted: None,
                            })
                        }
                        _ => unreachable!("Bucket is not full."), // Bucket filter should already be checked
                    }
                }
            } else {
                self.pending = Some(pending);
            }
        }

        None
    }

    /// Updates the status of the pending node, if any.
    pub fn update_pending(&mut self, status: NodeStatus) {
        if let Some(pending) = &mut self.pending {
            pending.node.status = status
        }
    }

    /// Updates the status of the node referred to by the given key, if it is
    /// in the bucket. If the node is not in the bucket, or the update would violate a bucket
    /// filter or incoming limits, returns an update result indicating the outcome.
    pub fn update_status(&mut self, key: &Key<TNodeId>, status: NodeStatus) -> UpdateResult {
        // Remove the node from its current position and then reinsert it
        // with the desired status, which puts it at the end of either the
        // prefix list of disconnected nodes or the suffix list of connected
        // nodes (i.e. most-recently disconnected or most-recently connected,
        // respectively).
        if let Some(pos) = self.position(key) {
            // Remove the node from its current position.
            let mut node = self.nodes.remove(pos.0);
            let old_status = node.status;
            node.status = status;

            // Adjust `first_connected_pos` accordingly.
            match old_status {
                NodeStatus::ConnectedIncoming | NodeStatus::ConnectedOutgoing => {
                    if self.first_connected_pos.map_or(false, |p| p == pos.0)
                        && pos.0 == self.nodes.len()
                    {
                        // It was the last connected node.
                        self.first_connected_pos = None
                    }
                }
                NodeStatus::Disconnected => {
                    self.first_connected_pos =
                        self.first_connected_pos.and_then(|p| p.checked_sub(1))
                }
            }
            // If the least-recently connected node re-establishes its
            // connected status, drop the pending node.
            if pos == Position(0) && status.is_connected() {
                self.pending = None
            }
            // Reinsert the node with the desired status.
            match self.insert(node) {
                InsertResult::Inserted => {
                    if node.status == old_status {
                        UpdateResult::NotModified
                    } else if old_status == NodeStatus::Disconnected {
                        // This means the status was updated from a disconnected state to connected
                        // state
                        UpdateResult::UpdatedAndPromoted
                    } else {
                        UpdateResult::Updated
                    }
                }
                InsertResult::TooManyIncoming => {
                    UpdateResult::UpdateFailed(FailureReason::TooManyIncoming)
                } // Node could not be inserted
                _ => unreachable!("The node is removed before being (re)inserted."),
            }
        } else {
            if let Some(pending) = &mut self.pending {
                if &pending.node.key == key {
                    pending.node.status = status;
                    UpdateResult::UpdatedPending
                } else {
                    UpdateResult::UpdateFailed(FailureReason::KeyNonExistant)
                }
            } else {
                UpdateResult::UpdateFailed(FailureReason::KeyNonExistant)
            }
        }
    }

    /// Updates the value of the node referred to by the given key, if it is
    /// in the bucket. If the node is not in the bucket, or the update would violate a bucket
    /// filter or incoming limits, returns false and removes the node from the bucket.
    pub fn update_value(&mut self, key: &Key<TNodeId>, value: TVal) -> UpdateResult {
        // Remove the node from its current position, check the filter and add it back in.

        if let Some(pos) = self.position(key) {
            // Remove the node from its current position.
            let mut node = self.nodes.remove(pos.0);
            let modified = node.value == value;
            node.value = value;

            // Adjust `first_connected_pos` accordingly.
            match node.status {
                NodeStatus::ConnectedIncoming | NodeStatus::ConnectedOutgoing => {
                    if self.first_connected_pos.map_or(false, |p| p == pos.0)
                        && pos.0 == self.nodes.len()
                    {
                        // It was the last connected node.
                        self.first_connected_pos = None
                    }
                }
                NodeStatus::Disconnected => {
                    self.first_connected_pos =
                        self.first_connected_pos.and_then(|p| p.checked_sub(1))
                }
            }
            // If the least-recently connected node re-establishes its
            // connected status, drop the pending node.
            if pos == Position(0) && node.status.is_connected() {
                self.pending = None
            }
            // Reinsert the node with the desired status.
            match self.insert(node) {
                InsertResult::Inserted => {
                    if modified {
                        UpdateResult::Updated
                    } else {
                        UpdateResult::NotModified
                    }
                }
                InsertResult::FailedFilter => {
                    UpdateResult::UpdateFailed(FailureReason::BucketFilter)
                } // The update could fail the bucket filter.
                _ => unreachable!("The node is removed before being (re)inserted."),
            }
        } else {
            if let Some(pending) = &mut self.pending {
                if &pending.node.key == key {
                    pending.node.value = value;
                    UpdateResult::UpdatedPending
                } else {
                    UpdateResult::UpdateFailed(FailureReason::KeyNonExistant)
                }
            } else {
                UpdateResult::UpdateFailed(FailureReason::KeyNonExistant)
            }
        }
    }

    /// Inserts a new node into the bucket with the given status.
    ///
    /// The status of the node to insert determines the result as follows:
    ///
    ///   * `NodeStatus::ConnectedIncoming` or `NodeStatus::ConnectedOutgoing`: If the bucket is full and either all nodes are connected
    ///     or there is already a pending node, insertion fails with `InsertResult::Full`.
    ///     If the bucket is full but at least one node is disconnected and there is no pending
    ///     node, the new node is inserted as pending, yielding `InsertResult::Pending`.
    ///     Otherwise the bucket has free slots and the new node is added to the end of the
    ///     bucket as the most-recently connected node.
    ///
    ///   * `NodeStatus::Disconnected`: If the bucket is full, insertion fails with
    ///     `InsertResult::Full`. Otherwise the bucket has free slots and the new node
    ///     is inserted at the position preceding the first connected node,
    ///     i.e. as the most-recently disconnected node. If there are no connected nodes,
    ///     the new node is added as the last element of the bucket.
    ///
    /// The insert can fail if a provided bucket filter does not pass. If a node is attempted
    /// to be inserted that doesn't pass the bucket filter, `InsertResult::FailedFilter` will be
    /// returned. Similarly, if the inserted node would violate the `max_incoming` value, the
    /// result will return `InsertResult::TooManyIncoming`.
    pub fn insert(&mut self, node: Node<TNodeId, TVal>) -> InsertResult<TNodeId> {
        // Prevent inserting duplicate nodes.
        if self.position(&node.key).is_some() {
            return InsertResult::NodeExists;
        }

        // check bucket filter
        if let Some(filter) = self.filter {
            if !filter.filter(node.value, self.iter().map(|(node, _)| &node.value)) {
                return InsertResult::FailedFilter;
            }
        }

        match node.status {
            NodeStatus::ConnectedIncoming | NodeStatus::ConnectedOutgoing => {
                if let NodeStatus::ConnectedOutgoing = node.status {
                    // check the maximum counter
                    if self.is_max_incoming() {
                        return InsertResult::TooManyIncoming;
                    }
                }
                if self.nodes.is_full() {
                    if self.first_connected_pos == Some(0) || self.pending.is_some() {
                        return InsertResult::Full;
                    } else {
                        self.pending = Some(PendingNode {
                            node,
                            replace: Instant::now() + self.pending_timeout,
                        });
                        return InsertResult::Pending {
                            disconnected: self.nodes[0].key.clone(),
                        };
                    }
                }
                let pos = self.nodes.len();
                self.first_connected_pos = self.first_connected_pos.or(Some(pos));
                self.nodes.push(node);
                InsertResult::Inserted
            }
            NodeStatus::Disconnected => {
                if self.nodes.is_full() {
                    return InsertResult::Full;
                }
                if let Some(ref mut first_connected_pos) = self.first_connected_pos {
                    self.nodes.insert(*first_connected_pos, node);
                    *first_connected_pos += 1;
                } else {
                    self.nodes.push(node);
                }
                InsertResult::Inserted
            }
        }
    }

    /// Removes a node from the bucket.
    pub fn remove(&mut self, key: &Key<TNodeId>) -> bool {
        if let Some(position) = self.position(key) {
            self.nodes.remove(position.0);
            true
        } else {
            false
        }
    }

    /// Gets the number of entries currently in the bucket.
    pub fn num_entries(&self) -> usize {
        self.nodes.len()
    }

    /// Gets the number of entries in the bucket that are considered connected.
    pub fn num_connected(&self) -> usize {
        self.first_connected_pos.map_or(0, |i| self.nodes.len() - i)
    }

    /// Gets the number of entries in the bucket that are considered disconnected.
    pub fn num_disconnected(&self) -> usize {
        self.nodes.len() - self.num_connected()
    }

    /// Gets the position of an node in the bucket.
    pub fn position(&self, key: &Key<TNodeId>) -> Option<Position> {
        self.nodes.iter().position(|p| &p.key == key).map(Position)
    }

    /// Gets a mutable reference to the node identified by the given key.
    ///
    /// Returns `None` if the given key does not refer to an node in the
    /// bucket.
    pub fn get_mut(&mut self, key: &Key<TNodeId>) -> Option<&mut Node<TNodeId, TVal>> {
        self.nodes.iter_mut().find(move |p| &p.key == key)
    }

    /// Returns whether the bucket has reached its maximum capacity of incoming nodes. This is used
    /// to determine if new nodes can be added to the bucket or not.
    fn is_max_incoming(&self) -> bool {
        self.nodes
            .iter()
            .filter(|node| node.status == NodeStatus::ConnectedIncoming)
            .count()
            >= self.max_incoming
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::NodeId;
    use quickcheck::*;
    use rand::Rng;
    use std::collections::VecDeque;

    impl Arbitrary for KBucket<NodeId, ()> {
        fn arbitrary<G: Gen>(g: &mut G) -> KBucket<NodeId, ()> {
            let timeout = Duration::from_secs(g.gen_range(1, g.size() as u64));
            let mut bucket = KBucket::<NodeId, ()>::new(timeout, None);
            let num_nodes = g.gen_range(1, MAX_NODES_PER_BUCKET + 1);
            for _ in 0..num_nodes {
                let key = Key::from(NodeId::random());
                loop {
                    let node = Node {
                        key: key.clone(),
                        value: (),
                        status: NodeStatus::arbitrary(g),
                    };
                    match bucket.insert(node) {
                        InsertResult::Inserted => break,
                        InsertResult::TooManyIncoming => {}
                        _ => panic!(),
                    }
                }
            }
            bucket
        }
    }

    impl Arbitrary for NodeStatus {
        fn arbitrary<G: Gen>(g: &mut G) -> NodeStatus {
            match g.gen_range(1, 3) {
                1 => NodeStatus::ConnectedOutgoing,
                2 => NodeStatus::ConnectedIncoming,
                3 => NodeStatus::Disconnected,
            }
        }
    }

    impl Arbitrary for Position {
        fn arbitrary<G: Gen>(g: &mut G) -> Position {
            Position(g.gen_range(0, MAX_NODES_PER_BUCKET))
        }
    }

    // Fill a bucket with random nodes with the given status.
    fn fill_bucket(bucket: &mut KBucket<NodeId, ()>, status: NodeStatus) {
        let num_entries_start = bucket.num_entries();
        for i in 0..MAX_NODES_PER_BUCKET - num_entries_start {
            let key = Key::from(NodeId::random());
            let node = Node {
                key,
                value: (),
                status,
            };
            assert_eq!(InsertResult::Inserted, bucket.insert(node));
            assert_eq!(bucket.num_entries(), num_entries_start + i + 1);
        }
    }

    #[test]
    fn ordering() {
        fn prop(status: Vec<NodeStatus>) -> bool {
            let mut bucket = KBucket::<NodeId, ()>::new(Duration::from_secs(1));

            // The expected lists of connected and disconnected nodes.
            let mut connected = VecDeque::new();
            let mut disconnected = VecDeque::new();

            // Fill the bucket, thereby populating the expected lists in insertion order.
            for status in status {
                let key = Key::from(NodeId::random());
                let node = Node {
                    key: key.clone(),
                    value: (),
                };
                let full = bucket.num_entries() == MAX_NODES_PER_BUCKET;
                if let InsertResult::Inserted = bucket.insert(node, status) {
                    let vec = match status {
                        NodeStatus::Connected => &mut connected,
                        NodeStatus::Disconnected => &mut disconnected,
                    };
                    if full {
                        vec.pop_front();
                    }
                    vec.push_back((status, key.clone()));
                }
            }

            // Get all nodes from the bucket, together with their status.
            let mut nodes = bucket
                .iter()
                .map(|(n, s)| (s, n.key.clone()))
                .collect::<Vec<_>>();

            // Split the list of nodes at the first connected node.
            let first_connected_pos = nodes.iter().position(|(s, _)| *s == NodeStatus::Connected);
            assert_eq!(bucket.first_connected_pos, first_connected_pos);
            let tail = first_connected_pos.map_or(Vec::new(), |p| nodes.split_off(p));

            // All nodes before the first connected node must be disconnected and
            // in insertion order. Similarly, all remaining nodes must be connected
            // and in insertion order.
            nodes == Vec::from(disconnected) && tail == Vec::from(connected)
        }

        quickcheck(prop as fn(_) -> _);
    }

    #[test]
    fn full_bucket() {
        let mut bucket = KBucket::<NodeId, ()>::new(Duration::from_secs(1), None);

        // Fill the bucket with disconnected nodes.
        fill_bucket(&mut bucket, NodeStatus::Disconnected);

        // Trying to insert another disconnected node fails.
        let key = Key::from(NodeId::random());
        let node = Node {
            key,
            value: (),
            status: NodeStatus::Disconnected,
        };
        match bucket.insert(node) {
            InsertResult::Full => {}
            x => panic!("{:?}", x),
        }

        // One-by-one fill the bucket with connected nodes, replacing the disconnected ones.
        for i in 0..MAX_NODES_PER_BUCKET {
            let (first, first_status) = bucket.iter().next().unwrap();
            let first_disconnected = first.clone();
            assert_eq!(first_status, NodeStatus::Disconnected);

            // Add a connected node, which is expected to be pending, scheduled to
            // replace the first (i.e. least-recently connected) node.
            let key = Key::from(NodeId::random());
            let node = Node {
                key: key.clone(),
                value: (),
                status: NodeStatus::ConnectedOutgoing,
            };
            match bucket.insert(node.clone()) {
                InsertResult::Pending { disconnected } => {
                    assert_eq!(disconnected, first_disconnected.key)
                }
                x => panic!("{:?}", x),
            }

            // Trying to insert another connected node fails.
            match bucket.insert(node.clone(), NodeStatus::Connected) {
                InsertResult::Full => {}
                x => panic!("{:?}", x),
            }

            assert!(bucket.pending().is_some());

            // Apply the pending node.
            let pending = bucket.pending_mut().expect("No pending node.");
            pending.set_ready_at(Instant::now() - Duration::from_secs(1));
            let result = bucket.apply_pending();
            assert_eq!(
                result,
                Some(AppliedPending {
                    inserted: key.clone(),
                    evicted: Some(first_disconnected)
                })
            );
            assert_eq!(Some((&node, NodeStatus::Connected)), bucket.iter().last());
            assert!(bucket.pending().is_none());
            assert_eq!(
                Some(MAX_NODES_PER_BUCKET - (i + 1)),
                bucket.first_connected_pos
            );
        }

        assert!(bucket.pending().is_none());
        assert_eq!(MAX_NODES_PER_BUCKET, bucket.num_entries());

        // Trying to insert another connected node fails.
        let key = Key::from(NodeId::random());
        let node = Node {
            key,
            value: (),
            status: NodeStatus::ConnectedOutgoing,
        };
        match bucket.insert(node) {
            InsertResult::Full => {}
            x => panic!("{:?}", x),
        }
    }

    #[test]
    fn full_bucket_discard_pending() {
        let mut bucket = KBucket::<NodeId, ()>::new(Duration::from_secs(1), None);
        fill_bucket(&mut bucket, NodeStatus::Disconnected);
        let (first, _) = bucket.iter().next().unwrap();
        let first_disconnected = first.clone();

        // Add a connected pending node.
        let key = Key::from(NodeId::random());
        let node = Node {
            key: key.clone(),
            value: (),
            status: NodeStatus::Connected,
        };
        if let InsertResult::Pending { disconnected } = bucket.insert(node) {
            assert_eq!(&disconnected, &first_disconnected.key);
        } else {
            panic!()
        }
        assert!(bucket.pending().is_some());

        // Update the status of the first disconnected node to be connected.
        bucket.update_status(&first_disconnected.key, NodeStatus::Connected);

        // The pending node has been discarded.
        assert!(bucket.pending().is_none());
        assert!(bucket.iter().all(|(n, _)| n.key != key));

        // The initially disconnected node is now the most-recently connected.
        assert_eq!(
            Some((&first_disconnected, NodeStatus::Connected)),
            bucket.iter().last()
        );
        assert_eq!(
            bucket.position(&first_disconnected.key).map(|p| p.0),
            bucket.first_connected_pos
        );
        assert_eq!(1, bucket.num_connected());
        assert_eq!(MAX_NODES_PER_BUCKET - 1, bucket.num_disconnected());
    }

    #[test]
    fn bucket_update_status() {
        fn prop(mut bucket: KBucket<NodeId, ()>, pos: Position, status: NodeStatus) -> bool {
            let num_nodes = bucket.num_entries();

            // Capture position and key of the random node to update.
            let pos = pos.0 % num_nodes;
            let key = bucket.nodes[pos].key.clone();

            // Record the (ordered) list of status of all nodes in the bucket.
            let mut expected = bucket
                .iter()
                .map(|(n, s)| (n.key.clone(), s))
                .collect::<Vec<_>>();

            // Update the node in the bucket.
            bucket.update_status(&key, status);

            // Check that the bucket now contains the node with the new status,
            // preserving the status and relative order of all other nodes.
            let expected_pos = match status {
                NodeStatus::Connected => num_nodes - 1,
                NodeStatus::Disconnected => bucket.first_connected_pos.unwrap_or(num_nodes) - 1,
            };
            expected.remove(pos);
            expected.insert(expected_pos, (key, status));
            let actual = bucket
                .iter()
                .map(|(n, s)| (n.key.clone(), s))
                .collect::<Vec<_>>();
            expected == actual
        }

        quickcheck(prop as fn(_, _, _) -> _);
    }
}
