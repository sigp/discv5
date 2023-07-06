use super::*;
use delay_map::HashMapDelay;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveRequestsError {
    InvalidState,
}

impl fmt::Display for ActiveRequestsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActiveRequestsError::InvalidState => {
                write!(f, "Invalid state: active requests mappings are not in sync")
            }
        }
    }
}

impl std::error::Error for ActiveRequestsError {}

pub(super) struct ActiveRequests {
    /// A list of raw messages we are awaiting a response from the remote.
    active_requests_mapping: HashMapDelay<NodeAddress, Vec<RequestCall>>,
    // WHOAREYOU messages do not include the source node id. We therefore maintain another
    // mapping of active_requests via message_nonce. This allows us to match WHOAREYOU
    // requests with active requests sent.
    /// A mapping of all pending active raw requests message nonces to their NodeAddress.
    active_requests_nonce_mapping: HashMap<MessageNonce, NodeAddress>,
}

impl ActiveRequests {
    pub fn new(request_timeout: Duration) -> Self {
        ActiveRequests {
            active_requests_mapping: HashMapDelay::new(request_timeout),
            active_requests_nonce_mapping: HashMap::new(),
        }
    }

    // Insert a new request into the active requests mapping.
    pub fn insert(&mut self, node_address: NodeAddress, request_call: RequestCall) {
        let nonce = *request_call.packet().message_nonce();
        let mut request_calls = self
            .active_requests_mapping
            .remove(&node_address)
            .unwrap_or_default();
        request_calls.push(request_call);
        self.active_requests_mapping
            .insert(node_address.clone(), request_calls);
        self.active_requests_nonce_mapping
            .insert(nonce, node_address);
    }

    // Remove a single request identified by its nonce.
    pub fn remove_by_nonce(
        &mut self,
        nonce: &MessageNonce,
    ) -> Result<(NodeAddress, RequestCall), ActiveRequestsError> {
        let node_address = self
            .active_requests_nonce_mapping
            .remove(nonce)
            .ok_or_else(|| ActiveRequestsError::InvalidState)?;
        let mut requests = self
            .active_requests_mapping
            .remove(&node_address)
            .ok_or_else(|| ActiveRequestsError::InvalidState)?;
        let index = match requests
            .iter()
            .position(|req| req.packet().message_nonce() == nonce)
        {
            Some(index) => index,
            None => {
                // if nonce req is missing, reinsert remaining requests into mapping
                self.active_requests_mapping
                    .insert(node_address.clone(), requests);
                return Err(ActiveRequestsError::InvalidState);
            }
        };
        let req = requests.remove(index);
        self.active_requests_mapping
            .insert(node_address.clone(), requests);
        Ok((node_address, req))
    }

    // Remove all requests associated with a node.
    pub fn remove_requests(
        &mut self,
        node_address: &NodeAddress,
    ) -> Result<Vec<RequestCall>, ActiveRequestsError> {
        let requests = self
            .active_requests_mapping
            .remove(&node_address)
            .ok_or_else(|| ActiveRequestsError::InvalidState)?;
        for req in &requests {
            self.active_requests_nonce_mapping
                .remove(req.packet().message_nonce());
        }
        Ok(requests)
    }

    // Remove a single request identified by its id.
    pub fn remove_request(
        &mut self,
        node_address: &NodeAddress,
        id: &RequestId,
    ) -> Result<RequestCall, ActiveRequestsError> {
        let reqs = self
            .active_requests_mapping
            .get(node_address)
            .ok_or_else(|| ActiveRequestsError::InvalidState)?;
        let index = reqs
            .iter()
            .position(|req| {
                let req_id: RequestId = req.id().into();
                &req_id == id
            })
            .ok_or_else(|| ActiveRequestsError::InvalidState)?;
        let nonce = reqs
            .get(index)
            .ok_or_else(|| ActiveRequestsError::InvalidState)?
            .packet()
            .message_nonce()
            .clone();
        // Remove the associated nonce mapping.
        let (_, request_call) = self.remove_by_nonce(&nonce)?;
        Ok(request_call)
    }

    /// Checks that `active_requests_mapping` and `active_requests_nonce_mapping` are in sync.
    // this function is only available in tests
    #[cfg(test)]
    // this makes is so that if there is a panic, the error is printed in the caller of this
    // function.
    #[track_caller]
    pub fn check_invariant(&self) {
        // First check that for every `MessageNonce` there is an associated `NodeAddress`.
        for (nonce, address) in self.active_requests_nonce_mapping.iter() {
            if !self.active_requests_mapping.contains_key(address) {
                panic!("Nonce {:?} maps to address {}, which does not exist in `active_requests_mapping`", nonce, address);
            }
        }

        for (address, requests) in self.active_requests_mapping.iter() {
            for req in requests {
                let nonce = req.packet().message_nonce();
                if !self.active_requests_nonce_mapping.contains_key(nonce) {
                    panic!("Address {} maps to request with nonce {:?}, which does not exist in `active_requests_nonce_mapping`", address, nonce);
                }
            }
        }
    }
}

impl Stream for ActiveRequests {
    type Item = Result<(NodeAddress, RequestCall), String>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.active_requests_mapping.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok((node_address, mut request_calls)))) => {
                let request_call = request_calls.remove(0);
                // reinsert remaining requests into mapping
                self.active_requests_mapping
                    .insert(node_address.clone(), request_calls);
                // remove the nonce mapping
                self.active_requests_nonce_mapping
                    .remove(request_call.packet().message_nonce())
                    .expect("Invariant violated: nonce mapping does not exist for request");
                Poll::Ready(Some(Ok((node_address, request_call))))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
