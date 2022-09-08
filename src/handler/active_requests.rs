use super::*;
use delay_map::HashMapDelay;
use more_asserts::debug_unreachable;

pub(crate) struct ActiveRequests {
    /// The default timeout for requests.
    request_timeout: Duration,
    /// A list of raw messages we are awaiting a response from the remote.
    active_requests_mapping: HashMapDelay<NodeAddress, RequestCall>,
    // WHOAREYOU messages do not include the source node id. We therefore maintain another
    // mapping of active_requests via message_nonce. This allows us to match WHOAREYOU
    // requests with active requests sent.
    /// A mapping of all pending active raw requests message nonces to their NodeAddress.
    active_requests_nonce_mapping: HashMap<MessageNonce, NodeAddress>,
}

impl ActiveRequests {
    pub(crate) fn new(request_timeout: Duration) -> Self {
        ActiveRequests {
            request_timeout,
            active_requests_mapping: HashMapDelay::new(request_timeout),
            active_requests_nonce_mapping: HashMap::new(),
        }
    }

    pub(crate) fn insert(
        &mut self,
        node_address: NodeAddress,
        request_call: RequestCall,
        local_node_id: &NodeId,
    ) {
        let nonce = *request_call.packet.message_nonce();
        let timeout = request_call.timeout(local_node_id, self.request_timeout);
        self.active_requests_mapping
            .insert_at(node_address.clone(), request_call, timeout);
        self.active_requests_nonce_mapping
            .insert(nonce, node_address);
    }

    pub(crate) fn get(&self, node_address: &NodeAddress) -> Option<&RequestCall> {
        self.active_requests_mapping.get(node_address)
    }

    pub(crate) fn remove_by_nonce(
        &mut self,
        nonce: &MessageNonce,
    ) -> Option<(NodeAddress, RequestCall)> {
        match self.active_requests_nonce_mapping.remove(nonce) {
            Some(node_address) => match self.active_requests_mapping.remove(&node_address) {
                Some(request_call) => Some((node_address, request_call)),
                None => {
                    debug_unreachable!("A matching request call doesn't exist");
                    error!("A matching request call doesn't exist");
                    None
                }
            },
            None => None,
        }
    }

    pub(crate) fn remove(&mut self, node_address: &NodeAddress) -> Option<RequestCall> {
        match self.active_requests_mapping.remove(node_address) {
            Some(request_call) => {
                // Remove the associated nonce mapping.
                match self
                    .active_requests_nonce_mapping
                    .remove(request_call.packet.message_nonce())
                {
                    Some(_) => Some(request_call),
                    None => {
                        debug_unreachable!("A matching nonce mapping doesn't exist");
                        error!("A matching nonce mapping doesn't exist");
                        None
                    }
                }
            }
            None => None,
        }
    }

    /// Checks that `active_requests_mapping` and `active_requests_nonce_mapping` are in sync.
    // this function is only available in tests
    #[cfg(test)]
    // this makes is so that if there is a panic, the error is printed in the caller of this
    // function.
    #[track_caller]
    pub(crate) fn check_invariant(&self) {
        // First check that for every `MessageNonce` there is an associated `NodeAddress`.
        for (nonce, address) in self.active_requests_nonce_mapping.iter() {
            if !self.active_requests_mapping.contains_key(address) {
                panic!("Nonce {:?} maps to address {}, which does not exist in `active_requests_mapping`", nonce, address);
            }
        }

        for (address, request) in self.active_requests_mapping.iter() {
            let nonce = request.packet.message_nonce();
            if !self.active_requests_nonce_mapping.contains_key(nonce) {
                panic!("Address {} maps to request with nonce {:?}, which does not exist in `active_requests_nonce_mapping`", address, nonce);
            }
        }
    }
}

impl Stream for ActiveRequests {
    type Item = Result<(NodeAddress, RequestCall), String>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.active_requests_mapping.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok((node_address, request_call)))) => {
                // Remove the associated nonce mapping.
                self.active_requests_nonce_mapping
                    .remove(request_call.packet.message_nonce());
                Poll::Ready(Some(Ok((node_address, request_call))))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
