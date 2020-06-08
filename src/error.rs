use rlp::DecoderError;

#[derive(Debug)]
pub enum Discv5Error {
    InvalidEnr,
    UnknownPublicKey,
    KeyTypeNotSupported(&'static str),
    KeyDerivationFailed,
    InvalidRemotePublicKey,
    InvalidSecretKey,
    InvalidSignature,
    SessionNotEstablished,
    RLPError(DecoderError),
    EncryptionFail(String),
    DecryptionFail(String),
    Custom(&'static str),
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestError {
    Timeout,
    ServiceNotStarted,
    ChannelFailed(String),
    InvalidEnr(String),
    EncryptionFailed(String),
    InvalidMultiaddr(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum QueryError {
    ServiceNotStarted,
    ChannelFailed(String),
    InvalidEnr(String),
    EncryptionFailed(String),
    InvalidMultiaddr(String),
}
