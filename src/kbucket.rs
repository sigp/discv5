// Copyright 2018 Parity Technologies (UK) Ltd.
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

//! Implementation of a Kademlia routing table as used by a single peer
//! participating in a Kademlia DHT.
//!
//! The entry point for the API of this module is a [`KBucketsTable`].
//!
//! ## Pending Insertions
//!
//! When the bucket associated with the `Key` of an inserted entry is full
//! but contains disconnected nodes, it accepts a [`PendingEntry`].
//! Pending entries are inserted lazily when their timeout is found to be expired
//! upon querying the `KBucketsTable`. When that happens, the `KBucketsTable` records
//! an [`AppliedPending`] result which must be consumed by calling [`take_applied_pending`]
//! regularly and / or after performing lookup operations like [`entry`] and [`closest`].
//!
//! [`entry`]: kbucket::KBucketsTable::entry
//! [`closest`]: kbucket::KBucketsTable::closest
//! [`AppliedPending`]: kbucket::AppliedPending
//! [`KBucketsTable`]: kbucket::KBucketsTable
//! [`take_applied_pending`]: kbucket::KBucketsTable::take_applied_pending
//! [`PendingEntry`]: kbucket::PendingEntry

// [Implementation Notes]
//
// 1. Routing Table Layout
//
// The routing table is currently implemented as a fixed-size "array" of
// buckets, ordered by increasing distance relative to a local key
// that identifies the local peer. This is an often-used, simplified
// implementation that approximates the properties of the b-tree (or prefix tree)
// implementation described in the full paper [0], whereby buckets are split on-demand.
// This should be treated as an implementation detail, however, so that the
// implementation may change in the future without breaking the API.
//
// 2. Replacement Cache
//
// In this implementation, the "replacement cache" for unresponsive peers
// consists of a single entry per bucket. Furthermore, this implementation is
// currently tailored to connection-oriented transports, meaning that the
// "LRU"-based ordering of entries in a bucket is actually based on the last reported
// connection status of the corresponding peers, from least-recently (dis)connected to
// most-recently (dis)connected, and controlled through the `Entry` API. As a result,
// the nodes in the buckets are not reordered as a result of RPC activity, but only as a
// result of nodes being marked as connected or disconnected. In particular,
// if a bucket is full and contains only entries for peers that are considered
// connected, no pending entry is accepted. See the `bucket` submodule for
// further details.
//
// [0]: https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf

mod bucket;
mod entry;
mod key;

pub use entry::*;

use crate::Enr;
use arrayvec::{self, ArrayVec};
use bucket::KBucket;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// Maximum number of k-buckets.
const NUM_BUCKETS: usize = 256;
/// Number of permitted nodes in the same /24 subnet
const MAX_NODES_PER_SUBNET_TABLE: usize = 10;

/// A key that can be returned from the `closest_keys` function, which indicates if the key matches the
/// predicate or not.
pub struct PredicateKey<TNodeId: Clone> {
    pub key: Key<TNodeId>,
    pub predicate_match: bool,
}

impl<TNodeId: Clone> AsRef<Key<TNodeId>> for PredicateKey<TNodeId> {
    fn as_ref(&self) -> &Key<TNodeId> {
        &self.key
    }
}

impl<TNodeId: Clone> Into<Key<TNodeId>> for PredicateKey<TNodeId> {
    fn into(self) -> Key<TNodeId> {
        self.key
    }
}

/// A `KBucketsTable` represents a Kademlia routing table.
#[derive(Debug, Clone)]
pub struct KBucketsTable<TNodeId, TVal> {
    /// The key identifying the local peer that owns the routing table.
    local_key: Key<TNodeId>,
    /// The buckets comprising the routing table.
    buckets: Vec<KBucket<TNodeId, TVal>>,
    /// The list of evicted entries that have been replaced with pending
    /// entries since the last call to [`KBucketsTable::take_applied_pending`].
    applied_pending: VecDeque<AppliedPending<TNodeId, TVal>>,
}

/// A (type-safe) index into a `KBucketsTable`, i.e. a non-negative integer in the
/// interval `[0, NUM_BUCKETS)`.
#[derive(Copy, Clone)]
struct BucketIndex(usize);

impl BucketIndex {
    /// Creates a new `BucketIndex` for a `Distance`.
    ///
    /// The given distance is interpreted as the distance from a `local_key` of
    /// a `KBucketsTable`. If the distance is zero, `None` is returned, in
    /// recognition of the fact that the only key with distance `0` to a
    /// `local_key` is the `local_key` itself, which does not belong in any
    /// bucket.
    fn new(d: &Distance) -> Option<BucketIndex> {
        (NUM_BUCKETS - d.0.leading_zeros() as usize)
            .checked_sub(1)
            .map(BucketIndex)
    }

    /// Gets the index value as an unsigned integer.
    fn get(self) -> usize {
        self.0
    }
}

impl<TNodeId, TVal> KBucketsTable<TNodeId, TVal>
where
    TNodeId: Clone,
{
    /// Creates a new, empty Kademlia routing table with entries partitioned
    /// into buckets as per the Kademlia protocol.
    ///
    /// The given `pending_timeout` specifies the duration after creation of
    /// a [`PendingEntry`] after which it becomes eligible for insertion into
    /// a full bucket, replacing the least-recently (dis)connected node.
    pub fn new(local_key: Key<TNodeId>, pending_timeout: Duration) -> Self {
        KBucketsTable {
            local_key,
            buckets: (0..NUM_BUCKETS)
                .map(|_| KBucket::new(pending_timeout))
                .collect(),
            applied_pending: VecDeque::new(),
        }
    }

    /// Removes a node from the routing table. Returns `true` of the node existed.
    pub fn remove(&mut self, key: &Key<TNodeId>) -> bool {
        let index = BucketIndex::new(&self.local_key.distance(key));
        if let Some(i) = index {
            let bucket = &mut self.buckets[i.get()];
            if let Some(applied) = bucket.apply_pending() {
                self.applied_pending.push_back(applied)
            }
            bucket.remove(key)
        } else {
            false
        }
    }

    /// Returns an `Entry` for the given key, representing the state of the entry
    /// in the routing table.
    pub fn entry<'a>(&'a mut self, key: &'a Key<TNodeId>) -> Entry<'a, TNodeId, TVal> {
        let index = BucketIndex::new(&self.local_key.distance(key));
        if let Some(i) = index {
            let bucket = &mut self.buckets[i.get()];
            if let Some(applied) = bucket.apply_pending() {
                self.applied_pending.push_back(applied)
            }
            Entry::new(bucket, key)
        } else {
            Entry::SelfEntry
        }
    }

    /// Returns an iterator over all the entries in the routing table.
    pub fn iter(&mut self) -> impl Iterator<Item = EntryRefView<'_, TNodeId, TVal>> {
        let applied_pending = &mut self.applied_pending;
        self.buckets.iter_mut().flat_map(move |table| {
            if let Some(applied) = table.apply_pending() {
                applied_pending.push_back(applied)
            }
            table.iter().map(move |(n, status)| EntryRefView {
                node: NodeRefView {
                    key: &n.key,
                    value: &n.value,
                },
                status,
            })
        })
    }

    /// Returns an iterator over all the entries in the routing table.
    /// Does not add pending node to kbucket to get an iterator which
    /// takes a reference instead of a mutable reference.
    pub fn iter_ref(&self) -> impl Iterator<Item = EntryRefView<'_, TNodeId, TVal>> {
        self.buckets.iter().flat_map(move |table| {
            table.iter().map(move |(n, status)| EntryRefView {
                node: NodeRefView {
                    key: &n.key,
                    value: &n.value,
                },
                status,
            })
        })
    }

    /// Consumes the next applied pending entry, if any.
    ///
    /// When an entry is attempted to be inserted and the respective bucket is full,
    /// it may be recorded as pending insertion after a timeout, see [`InsertResult::Pending`].
    ///
    /// If the oldest currently disconnected entry in the respective bucket does not change
    /// its status until the timeout of pending entry expires, it is evicted and
    /// the pending entry inserted instead. These insertions of pending entries
    /// happens lazily, whenever the `KBucketsTable` is accessed, and the corresponding
    /// buckets are updated accordingly. The fact that a pending entry was applied is
    /// recorded in the `KBucketsTable` in the form of `AppliedPending` results, which must be
    /// consumed by calling this function.
    pub fn take_applied_pending(&mut self) -> Option<AppliedPending<TNodeId, TVal>> {
        self.applied_pending.pop_front()
    }

    /// Returns an iterator over the keys that are contained in a kbucket, specified by a log2 distance.
    pub fn nodes_by_distances<'a>(
        &'a mut self,
        log2_distances: Vec<u64>,
        max_nodes: usize,
    ) -> Vec<EntryRefView<'a, TNodeId, TVal>> {
        let distances = log2_distances
            .into_iter()
            .filter(|&d| d > 0 && d <= (NUM_BUCKETS as u64))
            .collect::<Vec<_>>();

        // apply bending nodes
        for distance in &distances {
            // the log2 distance ranges from 1-256 and is always 1 more than the bucket index. For this
            // reason we subtract 1 from log2 distance to get the correct bucket index.
            let bucket = &mut self.buckets[(distance - 1) as usize];
            if let Some(applied) = bucket.apply_pending() {
                self.applied_pending.push_back(applied)
            }
        }

        // find the matching nodes
        let mut matching_nodes = Vec::new();

        // Note we search via distance in order
        for distance in distances {
            let bucket = &self.buckets[(distance - 1) as usize];
            for node in bucket.iter().map(|(n, status)| {
                let node = NodeRefView {
                    key: &n.key,
                    value: &n.value,
                };
                EntryRefView { node, status }
            }) {
                matching_nodes.push(node);
                // Exit early if we have found enough nodes
                if matching_nodes.len() >= max_nodes {
                    return matching_nodes;
                }
            }
        }
        matching_nodes
    }

    /// Returns an iterator over the keys closest to `target`, ordered by
    /// increasing distance.
    pub fn closest_keys<'a, T>(
        &'a mut self,
        target: &'a Key<T>,
    ) -> impl Iterator<Item = Key<TNodeId>> + 'a
    where
        T: Clone,
    {
        let distance = self.local_key.distance(target);
        ClosestIter {
            target,
            iter: None,
            table: self,
            buckets_iter: ClosestBucketsIter::new(distance),
            fmap: |b: &KBucket<_, _>| -> ArrayVec<_> {
                b.iter().map(|(n, _)| n.key.clone()).collect()
            },
        }
    }

    /// Returns an iterator over the keys closest to `target`, ordered by
    /// increasing distance specifying which keys agree with a value predicate.
    pub fn closest_keys_predicate<'a, T, F>(
        &'a mut self,
        target: &'a Key<T>,
        predicate: F,
    ) -> impl Iterator<Item = PredicateKey<TNodeId>> + 'a
    where
        T: Clone,
        F: Fn(&TVal) -> bool + 'a,
    {
        let distance = self.local_key.distance(target);
        ClosestIter {
            target,
            iter: None,
            table: self,
            buckets_iter: ClosestBucketsIter::new(distance),
            fmap: move |b: &KBucket<TNodeId, TVal>| -> ArrayVec<_> {
                b.iter()
                    .map(|(n, _)| PredicateKey {
                        key: n.key.clone(),
                        predicate_match: predicate(&n.value),
                    })
                    .collect()
            },
        }
    }

    /// Returns a reference to a bucket given the key. Returns None if bucket does not exist.
    pub fn get_bucket<'a>(&'a self, key: &Key<TNodeId>) -> Option<&'a KBucket<TNodeId, TVal>> {
        let index = BucketIndex::new(&self.local_key.distance(key));
        if let Some(i) = index {
            let bucket = &self.buckets[i.get()];
            Some(&bucket)
        } else {
            None
        }
    }

    /// Checks if key and value can be inserted into the kbuckets table.
    /// A single bucket can only have `MAX_NODES_PER_SUBNET_BUCKET` nodes per /24 subnet.
    /// The entire table can only have `MAX_NODES_PER_SUBNET_TABLE` nodes per /24 subnet.
    pub fn check(
        &self,
        key: &Key<TNodeId>,
        value: &TVal,
        f: impl Fn(&TVal, Vec<&TVal>, usize) -> bool,
    ) -> bool {
        let bucket = self.get_bucket(key);
        if let Some(b) = bucket {
            let others = self.iter_ref().map(|e| e.node.value).collect();
            f(value, others, MAX_NODES_PER_SUBNET_TABLE) && b.check(value, f)
        } else {
            true
        }
    }
}

/// An iterator over (some projection of) the closest entries in a
/// `KBucketsTable` w.r.t. some target `Key`.
struct ClosestIter<'a, TTarget, TNodeId, TVal, TMap, TOut> {
    /// A reference to the target key whose distance to the local key determines
    /// the order in which the buckets are traversed. The resulting
    /// array from projecting the entries of each bucket using `fmap` is
    /// sorted according to the distance to the target.
    target: &'a Key<TTarget>,
    /// A reference to all buckets of the `KBucketsTable`.
    table: &'a mut KBucketsTable<TNodeId, TVal>,
    /// The iterator over the bucket indices in the order determined by the
    /// distance of the local key to the target.
    buckets_iter: ClosestBucketsIter,
    /// The iterator over the entries in the currently traversed bucket.
    iter: Option<arrayvec::IntoIter<[TOut; MAX_NODES_PER_BUCKET]>>,
    /// The projection function / mapping applied on each bucket as
    /// it is encountered, producing the next `iter`ator.
    fmap: TMap,
}

/// An iterator over the bucket indices, in the order determined by the `Distance` of
/// a target from the `local_key`, such that the entries in the buckets are incrementally
/// further away from the target, starting with the bucket covering the target.
struct ClosestBucketsIter {
    /// The distance to the `local_key`.
    distance: Distance,
    /// The current state of the iterator.
    state: ClosestBucketsIterState,
}

/// Operating states of a `ClosestBucketsIter`.
enum ClosestBucketsIterState {
    /// The starting state of the iterator yields the first bucket index and
    /// then transitions to `ZoomIn`.
    Start(BucketIndex),
    /// The iterator "zooms in" to to yield the next bucket containing nodes that
    /// are incrementally closer to the local node but further from the `target`.
    /// These buckets are identified by a `1` in the corresponding bit position
    /// of the distance bit string. When bucket `0` is reached, the iterator
    /// transitions to `ZoomOut`.
    ZoomIn(BucketIndex),
    /// Once bucket `0` has been reached, the iterator starts "zooming out"
    /// to buckets containing nodes that are incrementally further away from
    /// both the local key and the target. These are identified by a `0` in
    /// the corresponding bit position of the distance bit string. When bucket
    /// `255` is reached, the iterator transitions to state `Done`.
    ZoomOut(BucketIndex),
    /// The iterator is in this state once it has visited all buckets.
    Done,
}

impl ClosestBucketsIter {
    fn new(distance: Distance) -> Self {
        let state = match BucketIndex::new(&distance) {
            Some(i) => ClosestBucketsIterState::Start(i),
            None => ClosestBucketsIterState::Done,
        };
        Self { distance, state }
    }

    fn next_in(&self, i: BucketIndex) -> Option<BucketIndex> {
        (0..i.get()).rev().find_map(|i| {
            if self.distance.0.bit(i) {
                Some(BucketIndex(i))
            } else {
                None
            }
        })
    }

    fn next_out(&self, i: BucketIndex) -> Option<BucketIndex> {
        (i.get() + 1..NUM_BUCKETS).find_map(|i| {
            if !self.distance.0.bit(i) {
                Some(BucketIndex(i))
            } else {
                None
            }
        })
    }
}

impl Iterator for ClosestBucketsIter {
    type Item = BucketIndex;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            ClosestBucketsIterState::Start(i) => {
                self.state = ClosestBucketsIterState::ZoomIn(i);
                Some(i)
            }
            ClosestBucketsIterState::ZoomIn(i) => {
                if let Some(i) = self.next_in(i) {
                    self.state = ClosestBucketsIterState::ZoomIn(i);
                    Some(i)
                } else {
                    let i = BucketIndex(0);
                    self.state = ClosestBucketsIterState::ZoomOut(i);
                    Some(i)
                }
            }
            ClosestBucketsIterState::ZoomOut(i) => {
                if let Some(i) = self.next_out(i) {
                    self.state = ClosestBucketsIterState::ZoomOut(i);
                    Some(i)
                } else {
                    self.state = ClosestBucketsIterState::Done;
                    None
                }
            }
            ClosestBucketsIterState::Done => None,
        }
    }
}

impl<TTarget, TNodeId, TVal, TMap, TOut> Iterator
    for ClosestIter<'_, TTarget, TNodeId, TVal, TMap, TOut>
where
    TNodeId: Clone,
    TMap: Fn(&KBucket<TNodeId, TVal>) -> ArrayVec<[TOut; MAX_NODES_PER_BUCKET]>,
    TOut: AsRef<Key<TNodeId>>,
{
    type Item = TOut;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.iter {
                Some(iter) => match iter.next() {
                    Some(k) => return Some(k),
                    None => self.iter = None,
                },
                None => {
                    if let Some(i) = self.buckets_iter.next() {
                        let bucket = &mut self.table.buckets[i.get()];
                        if let Some(applied) = bucket.apply_pending() {
                            self.table.applied_pending.push_back(applied)
                        }
                        let mut v = (self.fmap)(bucket);
                        v.sort_by(|a, b| {
                            self.target
                                .distance(a.as_ref())
                                .cmp(&self.target.distance(b.as_ref()))
                        });
                        self.iter = Some(v.into_iter());
                    } else {
                        return None;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::NodeId;

    #[test]
    fn basic_closest() {
        let local_key = Key::from(NodeId::random());
        let other_id = Key::from(NodeId::random());

        let mut table = KBucketsTable::<_, ()>::new(local_key, Duration::from_secs(5));
        if let Entry::Absent(entry) = table.entry(&other_id) {
            match entry.insert((), NodeStatus::Connected) {
                InsertResult::Inserted => (),
                _ => panic!(),
            }
        } else {
            panic!()
        }

        let res = table.closest_keys(&other_id).collect::<Vec<_>>();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], other_id);
    }

    #[test]
    fn update_local_id_fails() {
        let local_key = Key::from(NodeId::random());
        let mut table = KBucketsTable::<_, ()>::new(local_key.clone(), Duration::from_secs(5));
        match table.entry(&local_key) {
            Entry::SelfEntry => (),
            _ => panic!(),
        }
    }

    #[test]
    fn closest() {
        let local_key = Key::from(NodeId::random());
        let mut table = KBucketsTable::<_, ()>::new(local_key, Duration::from_secs(5));
        let mut count = 0;
        loop {
            if count == 100 {
                break;
            }
            let key = Key::from(NodeId::random());
            if let Entry::Absent(e) = table.entry(&key) {
                match e.insert((), NodeStatus::Connected) {
                    InsertResult::Inserted => count += 1,
                    _ => continue,
                }
            } else {
                panic!("entry exists")
            }
        }

        let mut expected_keys: Vec<_> = table
            .buckets
            .iter()
            .flat_map(|t| t.iter().map(|(n, _)| n.key.clone()))
            .collect();

        for _ in 0..10 {
            let target_key = Key::from(NodeId::random());
            let keys = table.closest_keys(&target_key).collect::<Vec<_>>();
            // The list of keys is expected to match the result of a full-table scan.
            expected_keys.sort_by_key(|k| k.distance(&target_key));
            assert_eq!(keys, expected_keys);
        }
    }

    #[test]
    fn applied_pending() {
        let local_key = Key::from(NodeId::random());
        let mut table = KBucketsTable::<_, ()>::new(local_key.clone(), Duration::from_millis(1));
        let expected_applied;
        let full_bucket_index;
        loop {
            let key = Key::from(NodeId::random());
            if let Entry::Absent(e) = table.entry(&key) {
                match e.insert((), NodeStatus::Disconnected) {
                    InsertResult::Full => {
                        if let Entry::Absent(e) = table.entry(&key) {
                            match e.insert((), NodeStatus::Connected) {
                                InsertResult::Pending { disconnected } => {
                                    expected_applied = AppliedPending {
                                        inserted: key.clone(),
                                        evicted: Some(Node {
                                            key: disconnected,
                                            value: (),
                                        }),
                                    };
                                    full_bucket_index = BucketIndex::new(&key.distance(&local_key));
                                    break;
                                }
                                _ => panic!(),
                            }
                        } else {
                            panic!()
                        }
                    }
                    _ => continue,
                }
            } else {
                panic!("entry exists")
            }
        }

        // Expire the timeout for the pending entry on the full bucket.`
        let full_bucket = &mut table.buckets[full_bucket_index.unwrap().get()];
        let elapsed = Instant::now() - Duration::from_secs(1);
        full_bucket.pending_mut().unwrap().set_ready_at(elapsed);

        match table.entry(&expected_applied.inserted) {
            Entry::Present(_, NodeStatus::Connected) => {}
            x => panic!("Unexpected entry: {:?}", x),
        }

        match table.entry(&expected_applied.evicted.as_ref().unwrap().key) {
            Entry::Absent(_) => {}
            x => panic!("Unexpected entry: {:?}", x),
        }

        assert_eq!(Some(expected_applied), table.take_applied_pending());
        assert_eq!(None, table.take_applied_pending());
    }
}

/// Takes an `ENR` to insert and a list of other `ENR`s to compare against.
/// Returns `true` if `ENR` can be inserted and `false` otherwise.
/// `enr` can be inserted if the count of enrs in `others` in the same /24 subnet as `ENR`
/// is less than `limit`.
pub fn ip_limiter(enr: &Enr, others: &[&Enr], limit: usize) -> bool {
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
