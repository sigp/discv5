#[derive(Zeroize, PartialEq)]
pub(crate) struct Keys {
    /// The Authentication response key.
    auth_resp_key: [u8; 16],

    /// The encryption key.
    encryption_key: [u8; 16],

    /// The decryption key.
    decryption_key: [u8; 16],
}
