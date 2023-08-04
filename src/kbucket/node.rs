use super::bucket::{Node, NodeStatus};
use super::key::Key;

/// Common interface for types that are insertable into a k-bucket and
/// hold information about a peer in the Kademlia DHT.
pub trait NodeRecord<TNodeId, TVal: Eq> {
    fn new(key: Key<TNodeId>, value: TVal, status: NodeStatus) -> Self;
    fn node_ref(&self) -> RecordRef<'_, TNodeId, TVal>;
    fn node_mut(&mut self) -> RecordMut<'_, TNodeId, TVal>;
    fn take(self) -> TakenRecord<TNodeId, TVal>;
}

/// Returned by [NodeRecord::node_mut(&self)]
pub struct RecordRef<'a, TNodeId, TVal> {
    pub key: &'a Key<TNodeId>,
    pub value: &'a TVal,
    pub status: &'a NodeStatus,
}

/// Returned by [NodeRecord::node_ref(&self)].
pub struct RecordMut<'a, TNodeId, TVal> {
    pub key: &'a mut Key<TNodeId>,
    pub value: &'a mut TVal,
    pub status: &'a mut NodeStatus,
}

pub struct TakenRecord<TNodeId, TVal> {
    pub key: Key<TNodeId>,
    pub value: TVal,
    pub status: NodeStatus,
}

impl<TNodeId, TVal: Eq> NodeRecord<TNodeId, TVal> for Node<TNodeId, TVal> {
    fn new(key: Key<TNodeId>, value: TVal, status: NodeStatus) -> Self {
        Node { key, value, status }
    }
    fn node_ref(&self) -> RecordRef<'_, TNodeId, TVal> {
        RecordRef {
            key: &self.key,
            value: &self.value,
            status: &self.status,
        }
    }
    fn node_mut(&mut self) -> RecordMut<'_, TNodeId, TVal> {
        RecordMut {
            key: &mut self.key,
            value: &mut self.value,
            status: &mut self.status,
        }
    }
    fn take(self) -> TakenRecord<TNodeId, TVal> {
        TakenRecord {
            key: self.key,
            value: self.value,
            status: self.status,
        }
    }
}
