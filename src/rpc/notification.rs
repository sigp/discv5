use super::{MessageType, Payload};
use crate::{
    packet::{MessageNonce, MESSAGE_NONCE_LENGTH},
    Enr,
};
use derive_more::Display;
use enr::NodeId;
use rlp::{DecoderError, Rlp, RlpStream};

/// Nonce of request that triggered the initiation of this hole punching attempt.
type NonceOfTimedOutMessage = MessageNonce;
/// Node id length in bytes.
pub const NODE_ID_LENGTH: usize = 32;

/// Unicast notifications [`RelayInitNotification`] and [`RelayMsgNotification`] sent over discv5.

/// A notification to initialise a one-shot relay circuit for hole-punching.
#[derive(Debug, Display, PartialEq, Eq, Clone)]
#[display(fmt = "Notification: RelayInit: Initiator: {_0}, Target: {_1}, Nonce: {_2:?}")]
pub struct RelayInitNotification(Enr, NodeId, NonceOfTimedOutMessage);

impl RelayInitNotification {
    pub fn new(
        initr_enr: Enr,
        tgt_node_id: NodeId,
        timed_out_msg_nonce: NonceOfTimedOutMessage,
    ) -> Self {
        Self(initr_enr, tgt_node_id, timed_out_msg_nonce)
    }

    pub fn initiator_enr(&self) -> &Enr {
        &self.0
    }

    pub fn target_node_id(&self) -> NodeId {
        self.1
    }
}

impl Payload for RelayInitNotification {
    /// Matches a notification type to its message type id.
    fn msg_type(&self) -> u8 {
        MessageType::RelayInit as u8
    }

    /// Encodes a notification message to RLP-encoded bytes.
    fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100);
        let msg_type = self.msg_type();
        buf.push(msg_type);
        let mut s = RlpStream::new();
        let Self(initiator, target, nonce) = self;

        s.begin_list(3);
        s.append(&initiator);
        s.append(&(&target.raw() as &[u8]));
        s.append(&(&nonce as &[u8]));

        buf.extend_from_slice(&s.out());
        buf
    }

    /// Decodes RLP-encoded bytes into a notification message.
    fn decode(_msg_type: u8, rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let initiator = rlp.val_at::<Enr>(0)?;

        let tgt_bytes = rlp.val_at::<Vec<u8>>(1)?;
        if tgt_bytes.len() > NODE_ID_LENGTH {
            return Err(DecoderError::RlpIsTooBig);
        }
        let mut tgt = [0u8; NODE_ID_LENGTH];
        tgt[NODE_ID_LENGTH - tgt_bytes.len()..].copy_from_slice(&tgt_bytes);
        let tgt = NodeId::from(tgt);

        let nonce = {
            let bytes = rlp.val_at::<Vec<u8>>(2)?;
            if bytes.len() > MESSAGE_NONCE_LENGTH {
                return Err(DecoderError::RlpIsTooBig);
            }
            let mut buf = [0u8; MESSAGE_NONCE_LENGTH];
            buf[MESSAGE_NONCE_LENGTH - bytes.len()..].copy_from_slice(&bytes);
            buf
        };

        Ok(Self(initiator, tgt, nonce))
    }
}

impl From<RelayInitNotification> for (Enr, NodeId, NonceOfTimedOutMessage) {
    fn from(value: RelayInitNotification) -> Self {
        let RelayInitNotification(initr_enr, tgt_node_id, timed_out_msg_nonce) = value;

        (initr_enr, tgt_node_id, timed_out_msg_nonce)
    }
}

/// The notification relayed to target of hole punch attempt.
#[derive(Debug, Display, PartialEq, Eq, Clone)]
#[display(fmt = "Notification: RelayMsg: Initiator: {_0}, Nonce: {_1:?}")]
pub struct RelayMsgNotification(Enr, NonceOfTimedOutMessage);

impl RelayMsgNotification {
    pub fn new(initr_enr: Enr, timed_out_msg_nonce: NonceOfTimedOutMessage) -> Self {
        RelayMsgNotification(initr_enr, timed_out_msg_nonce)
    }
}

impl Payload for RelayMsgNotification {
    /// Matches a notification type to its message type id.
    fn msg_type(&self) -> u8 {
        MessageType::RelayMsg as u8
    }

    /// Encodes a notification message to RLP-encoded bytes.
    fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100);
        let msg_type = self.msg_type();
        buf.push(msg_type);
        let mut s = RlpStream::new();
        let Self(initiator, nonce) = self;

        s.begin_list(2);
        s.append(&initiator);
        s.append(&(&nonce as &[u8]));

        buf.extend_from_slice(&s.out());
        buf
    }

    /// Decodes RLP-encoded bytes into a notification message.
    fn decode(_msg_type: u8, rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let initiator = rlp.val_at::<Enr>(0)?;

        let nonce = {
            let bytes = rlp.val_at::<Vec<u8>>(1)?;
            if bytes.len() > MESSAGE_NONCE_LENGTH {
                return Err(DecoderError::RlpIsTooBig);
            }
            let mut buf = [0u8; MESSAGE_NONCE_LENGTH];
            buf[MESSAGE_NONCE_LENGTH - bytes.len()..].copy_from_slice(&bytes);
            buf
        };

        Ok(Self(initiator, nonce))
    }
}

impl From<RelayMsgNotification> for (Enr, NonceOfTimedOutMessage) {
    fn from(value: RelayMsgNotification) -> Self {
        let RelayMsgNotification(initr_enr, timed_out_msg_nonce) = value;

        (initr_enr, timed_out_msg_nonce)
    }
}
