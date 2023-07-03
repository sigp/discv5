use super::*;
use delay_map::HashMapDelay;

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
    // Returns None if the nonce is not found.
    pub fn remove_by_nonce(&mut self, nonce: &MessageNonce) -> Option<(NodeAddress, RequestCall)> {
        let node_address = match self.active_requests_nonce_mapping.remove(nonce) {
            Some(node_address) => node_address,
            None => return None,
        };
        let mut requests = match self.active_requests_mapping.remove(&node_address) {
            Some(requests) => match requests.len() {
                0 => return None,
                _ => requests,
            },
            None => return None,
        };
        let index = match requests
            .iter()
            .position(|req| req.packet().message_nonce() == nonce)
        {
            Some(index) => index,
            None => {
                return None;
            }
        };
        let req = requests.remove(index);
        self.active_requests_mapping
            .insert(node_address.clone(), requests);
        Some((node_address, req))
    }

    // Remove all requests associated with a node.
    // Returns None if the node is not found.
    pub fn remove_requests(&mut self, node_address: &NodeAddress) -> Option<Vec<RequestCall>> {
        let requests = self
            .active_requests_mapping
            .remove(&node_address)
            .unwrap_or_default();
        for req in &requests {
            self.active_requests_nonce_mapping
                .remove(req.packet().message_nonce());
        }
        Some(requests)
    }

    // Remove a single request identified by its id.
    // Returns None if the node is not found.
    pub fn remove_request(
        &mut self,
        node_address: &NodeAddress,
        id: &RequestId,
    ) -> Option<RequestCall> {
        let mut reqs = match self.active_requests_mapping.remove(node_address) {
            Some(reqs) => reqs,
            None => return None,
        };
        match reqs.len() {
            0 => None,
            _ => {
                let index = reqs.iter().position(|req| {
                    let req_id = match req.id() {
                        HandlerReqId::Internal(id) | HandlerReqId::External(id) => id,
                    };
                    req_id == id
                });
                let index = match index {
                    Some(index) => index,
                    None => return None,
                };
                let req = reqs.remove(index);
                // Remove the associated nonce mapping.
                match self
                    .active_requests_nonce_mapping
                    .remove(req.packet().message_nonce())
                {
                    Some(_) => Some(req),
                    None => None,
                }
            }
        }
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

        for (address, request) in self.active_requests_mapping.iter() {
            for req in request {
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
        // should we move timeout management to active_requests_nonce_mapping?
        match self.active_requests_mapping.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok((node_address, mut request_calls)))) => {
                let request_call = request_calls.remove(0);
                self.active_requests_nonce_mapping
                    .remove(request_call.packet().message_nonce())
                    .expect("fuck");
                Poll::Ready(Some(Ok((node_address, request_call))))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
