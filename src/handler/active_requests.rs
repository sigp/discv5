use super::*;
use delay_map::HashMapDelay;
use more_asserts::debug_unreachable;
use std::collections::hash_map::Entry;

pub(super) struct ActiveRequests {
    /// A list of raw messages we are awaiting a response from the remote.
    active_requests_mapping: HashMap<NodeAddress, Vec<RequestCall>>,
    // WHOAREYOU messages do not include the source node id. We therefore maintain another
    // mapping of active_requests via message_nonce. This allows us to match WHOAREYOU
    // requests with active requests sent.
    /// A mapping of all active raw requests message nonces to their NodeAddress.
    active_requests_nonce_mapping: HashMapDelay<MessageNonce, NodeAddress>,
}

impl ActiveRequests {
    pub fn new(request_timeout: Duration) -> Self {
        ActiveRequests {
            active_requests_mapping: HashMap::new(),
            active_requests_nonce_mapping: HashMapDelay::new(request_timeout),
        }
    }

    /// Insert a new request into the active requests mapping.
    pub fn insert(&mut self, node_address: NodeAddress, request_call: RequestCall) {
        let nonce = *request_call.packet().message_nonce();
        self.active_requests_mapping
            .entry(node_address.clone())
            .or_insert_with(Vec::new)
            .push(request_call);
        self.active_requests_nonce_mapping
            .insert(nonce, node_address);
    }

    /// Remove a single request identified by its nonce.
    pub fn remove_by_nonce(&mut self, nonce: &MessageNonce) -> Option<(NodeAddress, RequestCall)> {
        let node_address = self.active_requests_nonce_mapping.remove(nonce)?;
        match self.active_requests_mapping.entry(node_address.clone()) {
            Entry::Vacant(_) => {
                debug_unreachable!("expected to find node address in active_requests_mapping");
                error!("expected to find node address in active_requests_mapping");
                None
            }
            Entry::Occupied(mut requests) => requests
                .get()
                .iter()
                .position(|req| req.packet().message_nonce() == nonce)
                .map(|index| (node_address, requests.get_mut().remove(index))),
        }
    }

    /// Remove all requests associated with a node.
    pub fn remove_requests(&mut self, node_address: &NodeAddress) -> Option<Vec<RequestCall>> {
        let requests = self.active_requests_mapping.remove(node_address)?;
        // Account for node addresses in `active_requests_nonce_mapping` with an empty list
        if requests.is_empty() {
            debug_unreachable!("expected to find requests in active_requests_mapping");
            return None;
        }
        for req in &requests {
            if self
                .active_requests_nonce_mapping
                .remove(req.packet().message_nonce())
                .is_none()
            {
                debug_unreachable!("expected to find req with nonce");
                error!("expected to find req with nonce");
            }
        }
        Some(requests)
    }

    /// Remove a single request identified by its id.
    pub fn remove_request(
        &mut self,
        node_address: &NodeAddress,
        id: &RequestId,
    ) -> Option<RequestCall> {
        match self.active_requests_mapping.entry(node_address.to_owned()) {
            Entry::Vacant(_) => None,
            Entry::Occupied(mut requests) => {
                let index = requests.get().iter().position(|req| {
                    let req_id: RequestId = req.id().into();
                    &req_id == id
                })?;
                let request_call = requests.get_mut().remove(index);
                // Remove the associated nonce mapping.
                self.active_requests_nonce_mapping
                    .remove(request_call.packet().message_nonce());
                Some(request_call)
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
        match self.active_requests_nonce_mapping.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok((nonce, node_address)))) => {
                match self.active_requests_mapping.entry(node_address.clone()) {
                    Entry::Vacant(_) => Poll::Ready(None),
                    Entry::Occupied(mut requests) => {
                        match requests
                            .get()
                            .iter()
                            .position(|req| req.packet().message_nonce() == &nonce)
                        {
                            Some(index) => Poll::Ready(Some(Ok((
                                node_address,
                                requests.get_mut().remove(index),
                            )))),
                            None => Poll::Ready(None),
                        }
                    }
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
