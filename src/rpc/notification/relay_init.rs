use super::Notification;
use crate::{
    impl_from_variant_unwrap,
    packet::{MessageNonce, MESSAGE_NONCE_LENGTH},
    Enr,
};
use enr::NodeId;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

/// Node id length in bytes.
const NODE_ID_LENGTH: usize = 32;
/// Nonce of request that triggered the initiation of this hole punching attempt.
type NonceOfTimedOutMessage = MessageNonce;

/// A notification sent from the initiator to the relay. Contains the enr of the initiator, the
/// nonce of the timed out request and the node id of the target.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelayInit(pub Enr, pub NodeId, pub NonceOfTimedOutMessage);

impl_from_variant_unwrap!(, Notification, RelayInit, Notification::RelayInit);

impl Encodable for RelayInit {
    fn rlp_append(&self, s: &mut RlpStream) {
        let RelayInit(initiator, target, nonce) = self;

        s.begin_list(3);
        s.append(initiator);
        s.append(&(&target.raw() as &[u8]));
        s.append(&(nonce as &[u8]));
    }
}

impl Decodable for RelayInit {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
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

        let nonce_bytes = rlp.val_at::<Vec<u8>>(2)?;
        if nonce_bytes.len() > MESSAGE_NONCE_LENGTH {
            return Err(DecoderError::RlpIsTooBig);
        }
        let mut nonce = [0u8; MESSAGE_NONCE_LENGTH];
        nonce[MESSAGE_NONCE_LENGTH - nonce_bytes.len()..].copy_from_slice(&nonce_bytes);

        Ok(RelayInit(initiator, tgt, nonce))
    }
}

impl fmt::Display for RelayInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initiator = &self.0;
        let tgt = hex::encode(self.1);
        let nonce = hex::encode(self.2);
        write!(
            f,
            "RelayInit: Initiator: {}, Target: 0x{}..{}, Nonce: 0x{}..{}",
            initiator,
            &tgt[0..4],
            &tgt[tgt.len() - 4..],
            &nonce[0..2],
            &nonce[nonce.len() - 2..]
        )
    }
}
