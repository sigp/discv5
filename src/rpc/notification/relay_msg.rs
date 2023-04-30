use super::Notification;
use crate::{
    impl_from_variant_unwrap,
    packet::{MessageNonce, MESSAGE_NONCE_LENGTH},
    Enr,
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

// Nonce of request that triggered the initiation of this hole punching attempt.
type NonceOfTimedOutMessage = MessageNonce;

/// A notification sent from the initiator to the relay. Contains the enr of the initiator and the
/// nonce of the timed out request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelayMsg(pub Enr, pub NonceOfTimedOutMessage);

impl_from_variant_unwrap!(, Notification, RelayMsg, Notification::RelayMsg);

impl Encodable for RelayMsg {
    fn rlp_append(&self, s: &mut RlpStream) {
        let RelayMsg(initiator, nonce) = self;

        s.begin_list(2);
        s.append(initiator);
        s.append(&(nonce as &[u8]));
    }
}

impl Decodable for RelayMsg {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let initiator = rlp.val_at::<Enr>(0)?;

        let nonce_bytes = rlp.val_at::<Vec<u8>>(2)?;
        if nonce_bytes.len() > MESSAGE_NONCE_LENGTH {
            return Err(DecoderError::RlpIsTooBig);
        }
        let mut nonce = [0u8; MESSAGE_NONCE_LENGTH];
        nonce[MESSAGE_NONCE_LENGTH - nonce_bytes.len()..].copy_from_slice(&nonce_bytes);

        Ok(RelayMsg(initiator, nonce).into())
    }
}

impl fmt::Display for RelayMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initiator = &self.0;
        let nonce = hex::encode(self.1);
        write!(
            f,
            "RelayMsg: Initiator: {}, Nonce: 0x{}..{}",
            initiator,
            &nonce[0..2],
            &nonce[nonce.len() - 2..]
        )
    }
}
