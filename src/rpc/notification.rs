use super::{Payload, RELAYINIT_MSG_TYPE, RELAYMSG_MSG_TYPE};
use crate::{
    packet::{MessageNonce, MESSAGE_NONCE_LENGTH},
    Enr,
};
use enr::NodeId;
use parse_display_derive::Display;
use rlp::{DecoderError, Rlp, RlpStream};

/// Nonce of request that triggered the initiation of this hole punching attempt.
type NonceOfTimedOutMessage = MessageNonce;
/// Node id length in bytes.
pub const NODE_ID_LENGTH: usize = 32;

/// A unicast notification sent over discv5.
#[derive(Debug, Display, PartialEq, Eq, Clone)]
pub enum Notification {
    /// A notification to initialise a one-shot relay circuit for hole-punching.
    #[display("Notification: RelayInit: Initiator: {0}, Target: {1}, Nonce: {:2}")]
    RelayInit(Enr, NodeId, NonceOfTimedOutMessage),
    /// The notification relayed to target of hole punch attempt.
    #[display("Notification: RelayMsg: Initiator: {0}, Nonce: {:1}")]
    RelayMsg(Enr, NonceOfTimedOutMessage),
}

impl Payload for Notification {
    /// Matches a notification type to its message type id.
    fn msg_type(&self) -> u8 {
        match self {
            Self::RelayInit(..) => RELAYINIT_MSG_TYPE,
            Self::RelayMsg(..) => RELAYMSG_MSG_TYPE,
        }
    }

    /// Encodes a notification message to RLP-encoded bytes.
    fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100);
        let msg_type = self.msg_type();
        buf.push(msg_type);
        let mut s = RlpStream::new();
        match self {
            Self::RelayInit(initiator, target, nonce) => {
                s.begin_list(3);
                s.append(&initiator);
                s.append(&(&target.raw() as &[u8]));
                s.append(&(&nonce as &[u8]));
            }
            Self::RelayMsg(initiator, nonce) => {
                s.begin_list(2);
                s.append(&initiator);
                s.append(&(&nonce as &[u8]));
            }
        }
        buf.extend_from_slice(&s.out());
        buf
    }

    /// Decodes RLP-encoded bytes into a notification message.
    fn decode(msg_type: u8, rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        match msg_type {
            RELAYINIT_MSG_TYPE => {
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

                Ok(Notification::RelayInit(initiator, tgt, nonce))
            }
            RELAYMSG_MSG_TYPE => {
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

                Ok(Notification::RelayMsg(initiator, nonce))
            }
            _ => unreachable!("Implementation does not adhere to wire protocol"),
        }
    }
}
