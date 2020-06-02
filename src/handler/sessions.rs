
struct Session {
    pub contact: NodeContact,
    current_keys: Keys,
    awaiting_keys: Option<Keys>,
    pub trusted: bool
}

impl Session {
    pub fn new(contact: NodeContact, keys: Keys) -> Self {
        Session {
            contact,
            current_keys: Keys,
            awaiting_keys: None,
            trusted: false
        }
    }
}

/// Generates session keys from an authentication header. If the IP of the ENR does not match the
/// source IP address, we consider this session untrusted. The output returns a boolean which
/// specifies if the Session is trusted or not.
pub(crate) fn establish_from_header(
    local_key: &CombinedKey,
    local_id: &NodeId,
    remote_id: &NodeId,
    challenge: &Challenge,
    auth_header: &AuthHeader,
) -> Result<Session, Discv5Error> {
    // generate session keys
    let (decryption_key, encryption_key, auth_resp_key) = crypto::derive_keys_from_pubkey(
        local_key,
        local_id,
        remote_id,
        &challenge.nonce,
        &auth_header.ephemeral_pubkey,
    )?;

    // decrypt the authentication header
    let auth_response = crypto::decrypt_authentication_header(&auth_resp_key, auth_header)?;

    // check and verify a potential ENR update
    let session_enr = 
        match (auth_response.node_record, challenge.remote_enr) { 
            (Some(new_enr), Some(known_enr) => {
                if new_enr.seq() > known_enr.seq() {
                    new_enr
                else {
                    known_enr
                }
            }
            }
            (Some(new_enr), None) => new_enr
            (None, Some(known_enr) => known_enr
            (None, None) => {
                warn!("Peer did not respond with their ENR. Session could not be established. Node: {}",remote_id);
                return Err(Discv5Error::SessionNotEstablished);
            }
    };

    // ENR must exist here
    let remote_public_key = session_enr.public_key();

    // verify the auth header nonce
    if !crypto::verify_authentication_nonce(
        &remote_public_key,
        &auth_header.ephemeral_pubkey,
        &challenge.nonce,
        &auth_response.signature,
    ) {
        return Err(Discv5Error::InvalidSignature);
    }

    let keys = Keys {
        auth_resp_key,
        encryption_key,
        decryption_key,
    };

    let contact = session_enr.into();

    Session::new(contact, keys)
}

