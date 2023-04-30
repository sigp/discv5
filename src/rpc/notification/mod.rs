use super::{REALYINIT_MSG_TYPE, REALYMSG_MSG_TYPE};
use crate::{impl_from_variant_wrap, packet::MessageNonce};
use parse_display_derive::Display;
use rlp::{Decodable, DecoderError, Rlp, RlpStream};

mod relay_init;
mod relay_msg;

pub use relay_init::RelayInit;
pub use relay_msg::RelayMsg;

/// Nonce of request that triggered the initiation of this hole punching attempt.
type NonceOfTimedOutMessage = MessageNonce;

/// A unicast notification sent over discv5.
#[derive(Debug, Display, PartialEq, Eq, Clone)]
pub enum Notification {
    /// A notification to initialise a one-shot relay circuit for hole-punching.
    #[display("Notification: {0}")]
    RelayInit(pub Enr, pub NodeId, pub NonceOfTimedOutMessage),
    /// The notification relayed to target of hole punch attempt.
    #[display("Notification: {0}")]
    RelayMsg(pub Enr, pub NonceOfTimedOutMessage),
}

impl_from_variant_wrap!(, RelayInit, Notification, Self::RelayInit);
impl_from_variant_wrap!(, RelayMsg, Notification, Self::RelayMsg);

impl Notification {
    pub fn msg_type(&self) -> u8 {
        match self {
            Self::RelayInit(..) => 7,
            Self::RelayMsg(..) => 8,
        }
    }

    /// Encodes a notification message to RLP-encoded bytes.
    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100);
        let msg_type = self.msg_type();
        buf.push(msg_type);
        let mut s = RlpStream::new();
        let _ = match self {
            Self::RelayInit(notif) => s.append(&notif),
            Self::RelayMsg(notif) => s.append(&notif),
        };
        buf.extend_from_slice(&s.out());
        buf
    }

    /// Decodes RLP-encoded bytes into a notification message.
    pub fn decode(msg_type: u8, rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        match msg_type {
            REALYINIT_MSG_TYPE => Ok(RelayInit::decode(rlp)?.into()),
            REALYMSG_MSG_TYPE => Ok(RelayMsg::decode(rlp)?.into()),
            _ => {
                return Err(DecoderError::Custom(
                    "Unknown RPC notification message type",
                ))
            }
        }
    }
}
