use thiserror::Error;

use crate::Discv5Error;

/// An error occurred whilst attempting to hole punch NAT.
#[derive(Debug, Error)]
pub enum Error {
    #[error("NAT error, failed as initiator of a hole punch attempt, {0}")]
    Initiator(Discv5Error),
    #[error("NAT error, failed as relay of a hole punch attempt, {0}")]
    Relay(Discv5Error),
    #[error("NAT error, failed as target of a hole punch attempt, {0}")]
    Target(Discv5Error),
}
