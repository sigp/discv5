#![cfg(test)]

use super::*;
use crate::{
    packet::DefaultProtocolId,
    return_if_ipv6_is_not_supported,
    rpc::{Request, Response},
    ConfigBuilder, IpMode,
};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Add,
};

use crate::{
    handler::{session::build_dummy_session, HandlerOut::RequestFailed},
    RequestError::SelfRequest,
};
use active_requests::ActiveRequests;
use enr::EnrBuilder;
use std::time::Duration;
use tokio::time::sleep;

fn init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

async fn build_handler<P: ProtocolIdentity>(
    enr: Enr,
    key: CombinedKey,
    config: Config,
) -> (
    oneshot::Sender<()>,
    mpsc::UnboundedSender<HandlerIn>,
    mpsc::Receiver<HandlerOut>,
    Handler,
) {
    let mut listen_sockets = SmallVec::default();
    listen_sockets.push((Ipv4Addr::LOCALHOST, 9000).into());
    let node_id = enr.node_id();
    let filter_expected_responses = Arc::new(RwLock::new(HashMap::new()));

    let socket = {
        let socket_config = {
            let filter_config = FilterConfig {
                enabled: config.enable_packet_filter,
                rate_limiter: config.filter_rate_limiter.clone(),
                max_nodes_per_ip: config.filter_max_nodes_per_ip,
                max_bans_per_ip: config.filter_max_bans_per_ip,
            };

            socket::SocketConfig {
                executor: config.executor.clone().expect("Executor must exist"),
                filter_config,
                listen_config: config.listen_config.clone(),
                local_node_id: node_id,
                expected_responses: filter_expected_responses.clone(),
                ban_duration: config.ban_duration,
            }
        };

        Socket::new::<P>(socket_config).await.unwrap()
    };
    let (handler_send, service_recv) = mpsc::unbounded_channel();
    let (service_send, handler_recv) = mpsc::channel(50);
    let (exit_sender, exit) = oneshot::channel();

    let handler = Handler {
        request_retries: config.request_retries,
        node_id,
        enr: Arc::new(RwLock::new(enr)),
        key: Arc::new(RwLock::new(key)),
        active_requests: ActiveRequests::new(config.request_timeout),
        pending_requests: HashMap::new(),
        filter_expected_responses,
        sessions: LruTimeCache::new(config.session_timeout, Some(config.session_cache_capacity)),
        one_time_sessions: LruTimeCache::new(
            Duration::from_secs(ONE_TIME_SESSION_TIMEOUT),
            Some(ONE_TIME_SESSION_CACHE_CAPACITY),
        ),
        active_challenges: HashMapDelay::new(config.request_timeout),
        service_recv,
        service_send,
        listen_sockets,
        socket,
        exit,
    };
    (exit_sender, handler_send, handler_recv, handler)
}

macro_rules! arc_rw {
    ( $x: expr ) => {
        Arc::new(RwLock::new($x))
    };
}

#[tokio::test]
// Tests the construction and sending of a simple message
async fn simple_session_message() {
    init();

    let sender_port = 5000;
    let receiver_port = 5001;
    let ip = "127.0.0.1".parse().unwrap();

    let key1 = CombinedKey::generate_secp256k1();
    let key2 = CombinedKey::generate_secp256k1();

    let sender_enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(sender_port)
        .build(&key1)
        .unwrap();
    let receiver_enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(receiver_port)
        .build(&key2)
        .unwrap();

    let sender_listen_config = ListenConfig::Ipv4 {
        ip: sender_enr.ip4().unwrap(),
        port: sender_enr.udp4().unwrap(),
    };
    let sender_config = ConfigBuilder::new(sender_listen_config)
        .enable_packet_filter()
        .build();
    let (_exit_send, sender_send, _sender_recv) = Handler::spawn::<DefaultProtocolId>(
        arc_rw!(sender_enr.clone()),
        arc_rw!(key1),
        sender_config,
    )
    .await
    .unwrap();

    let receiver_listen_config = ListenConfig::Ipv4 {
        ip: receiver_enr.ip4().unwrap(),
        port: receiver_enr.udp4().unwrap(),
    };
    let receiver_config = ConfigBuilder::new(receiver_listen_config)
        .enable_packet_filter()
        .build();
    let (_exit_recv, recv_send, mut receiver_recv) = Handler::spawn::<DefaultProtocolId>(
        arc_rw!(receiver_enr.clone()),
        arc_rw!(key2),
        receiver_config,
    )
    .await
    .unwrap();

    let send_message = Box::new(Request {
        id: RequestId(vec![1]),
        body: RequestBody::Ping { enr_seq: 1 },
    });

    let _ = sender_send.send(HandlerIn::Request(
        receiver_enr.into(),
        send_message.clone(),
    ));

    let receiver = async move {
        loop {
            if let Some(message) = receiver_recv.recv().await {
                match message {
                    HandlerOut::WhoAreYou(wru_ref) => {
                        let _ =
                            recv_send.send(HandlerIn::WhoAreYou(wru_ref, Some(sender_enr.clone())));
                    }
                    HandlerOut::Request(_, request) => {
                        assert_eq!(request, send_message);
                        return;
                    }
                    _ => {}
                }
            }
        }
    };

    tokio::select! {
        _ = receiver => {}
        _ = sleep(Duration::from_millis(500)) => {
            panic!("Test timed out");
        }
    }
}

#[tokio::test]
// Tests sending multiple messages on an encrypted session
async fn multiple_messages() {
    init();
    let sender_port = 5002;
    let receiver_port = 5003;
    let ip = "127.0.0.1".parse().unwrap();
    let key1 = CombinedKey::generate_secp256k1();
    let key2 = CombinedKey::generate_secp256k1();

    let sender_enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(sender_port)
        .build(&key1)
        .unwrap();

    let receiver_enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(receiver_port)
        .build(&key2)
        .unwrap();

    // Build sender handler
    let (sender_exit, sender_send, mut sender_recv, mut handler) = {
        let sender_listen_config = ListenConfig::Ipv4 {
            ip: sender_enr.ip4().unwrap(),
            port: sender_enr.udp4().unwrap(),
        };
        let sender_config = ConfigBuilder::new(sender_listen_config).build();
        build_handler::<DefaultProtocolId>(sender_enr.clone(), key1, sender_config).await
    };
    let sender = async move {
        // Start sender handler.
        handler.start::<DefaultProtocolId>().await;
        // After the handler has been terminated test the handler's states.
        assert!(handler.pending_requests.is_empty());
        assert_eq!(0, handler.active_requests.count().await);
        assert!(handler.active_challenges.is_empty());
        assert!(handler.filter_expected_responses.read().is_empty());
    };

    // Build receiver handler
    let (receiver_exit, receiver_send, mut receiver_recv, mut handler) = {
        let receiver_listen_config = ListenConfig::Ipv4 {
            ip: receiver_enr.ip4().unwrap(),
            port: receiver_enr.udp4().unwrap(),
        };
        let receiver_config = ConfigBuilder::new(receiver_listen_config).build();
        build_handler::<DefaultProtocolId>(receiver_enr.clone(), key2, receiver_config).await
    };
    let receiver = async move {
        // Start receiver handler.
        handler.start::<DefaultProtocolId>().await;
        // After the handler has been terminated test the handler's states.
        assert!(handler.pending_requests.is_empty());
        assert_eq!(0, handler.active_requests.count().await);
        assert!(handler.active_challenges.is_empty());
        assert!(handler.filter_expected_responses.read().is_empty());
    };

    let send_message = Box::new(Request {
        id: RequestId(vec![1]),
        body: RequestBody::Ping { enr_seq: 1 },
    });

    // sender to send the first message then await for the session to be established
    let _ = sender_send.send(HandlerIn::Request(
        receiver_enr.clone().into(),
        send_message.clone(),
    ));

    let pong_response = Response {
        id: RequestId(vec![1]),
        body: ResponseBody::Pong {
            enr_seq: 1,
            ip: ip.into(),
            port: sender_port,
        },
    };

    let messages_to_send = 5usize;

    let mut message_count = 0usize;
    let recv_send_message = send_message.clone();

    let sender_ops = async move {
        let mut response_count = 0usize;
        loop {
            match sender_recv.recv().await {
                Some(HandlerOut::Established(_, _, _)) => {
                    // now the session is established, send the rest of the messages
                    for _ in 0..messages_to_send - 1 {
                        let _ = sender_send.send(HandlerIn::Request(
                            receiver_enr.clone().into(),
                            send_message.clone(),
                        ));
                    }
                }
                Some(HandlerOut::Response(_, _)) => {
                    response_count += 1;
                    if response_count == messages_to_send {
                        // Notify the handlers that the message exchange has been completed.
                        sender_exit.send(()).unwrap();
                        receiver_exit.send(()).unwrap();
                        return;
                    }
                }
                _ => continue,
            };
        }
    };

    let receiver_ops = async move {
        loop {
            match receiver_recv.recv().await {
                Some(HandlerOut::WhoAreYou(wru_ref)) => {
                    let _ =
                        receiver_send.send(HandlerIn::WhoAreYou(wru_ref, Some(sender_enr.clone())));
                }
                Some(HandlerOut::Request(addr, request)) => {
                    assert_eq!(request, recv_send_message);
                    message_count += 1;
                    // required to send a pong response to establish the session
                    let _ = receiver_send
                        .send(HandlerIn::Response(addr, Box::new(pong_response.clone())));
                    if message_count == messages_to_send {
                        return;
                    }
                }
                _ => {
                    continue;
                }
            }
        }
    };

    let sleep_future = sleep(Duration::from_millis(100));
    let message_exchange = async move {
        let _ = tokio::join!(sender, sender_ops, receiver, receiver_ops);
    };

    tokio::select! {
        _ = message_exchange => {}
        _ = sleep_future => {
            panic!("Test timed out");
        }
    }
}

fn create_node() -> Enr {
    let key = CombinedKey::generate_secp256k1();
    let ip = "127.0.0.1".parse().unwrap();
    let port = 8080 + rand::random::<u16>() % 1000;
    EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(port)
        .build(&key)
        .unwrap()
}

fn create_req_call(node: &Enr) -> (RequestCall, NodeAddress) {
    let node_contact: NodeContact = node.clone().into();
    let packet = Packet::new_random(&node.node_id()).unwrap();
    let id = HandlerReqId::Internal(RequestId::random());
    let request = RequestBody::Ping { enr_seq: 1 };
    let initiating_session = true;
    let node_addr = node_contact.node_address();
    let req = RequestCall::new(node_contact, packet, id, request, initiating_session);
    (req, node_addr)
}

#[tokio::test]
async fn test_active_requests_insert() {
    const EXPIRY: Duration = Duration::from_secs(5);
    let mut active_requests = ActiveRequests::new(EXPIRY);

    let node_1 = create_node();
    let node_2 = create_node();
    let (req_1, req_1_addr) = create_req_call(&node_1);
    let (req_2, req_2_addr) = create_req_call(&node_2);
    let (req_3, req_3_addr) = create_req_call(&node_2);

    // insert the pair and verify the mapping remains in sync
    active_requests.insert(req_1_addr, req_1);
    active_requests.check_invariant();
    active_requests.insert(req_2_addr, req_2);
    active_requests.check_invariant();
    active_requests.insert(req_3_addr, req_3);
    active_requests.check_invariant();
}

#[tokio::test]
async fn test_active_requests_remove_requests() {
    const EXPIRY: Duration = Duration::from_secs(5);
    let mut active_requests = ActiveRequests::new(EXPIRY);

    let node_1 = create_node();
    let node_2 = create_node();
    let (req_1, req_1_addr) = create_req_call(&node_1);
    let (req_2, req_2_addr) = create_req_call(&node_2);
    let (req_3, req_3_addr) = create_req_call(&node_2);
    active_requests.insert(req_1_addr.clone(), req_1);
    active_requests.insert(req_2_addr.clone(), req_2);
    active_requests.insert(req_3_addr.clone(), req_3);
    active_requests.check_invariant();
    let reqs = active_requests.remove_requests(&req_1_addr).unwrap();
    assert_eq!(reqs.len(), 1);
    active_requests.check_invariant();
    let reqs = active_requests.remove_requests(&req_2_addr).unwrap();
    assert_eq!(reqs.len(), 2);
    active_requests.check_invariant();
    assert!(active_requests.remove_requests(&req_3_addr).is_none());
}

#[tokio::test]
async fn test_active_requests_remove_requests_except() {
    const EXPIRY: Duration = Duration::from_secs(5);
    let mut active_requests = ActiveRequests::new(EXPIRY);

    let node_1 = create_node();
    let node_2 = create_node();
    let (req_1, req_1_addr) = create_req_call(&node_1);
    let (req_2, req_2_addr) = create_req_call(&node_2);
    let (req_3, req_3_addr) = create_req_call(&node_2);

    let req_2_nonce = req_2.packet().header.message_nonce;
    let req_3_id: RequestId = req_3.id().into();

    active_requests.insert(req_1_addr, req_1);
    active_requests.insert(req_2_addr.clone(), req_2);
    active_requests.insert(req_3_addr, req_3);

    let removed_requests = active_requests
        .remove_requests_except(&req_2_addr, &req_2_nonce)
        .unwrap();
    active_requests.check_invariant();

    assert_eq!(1, removed_requests.len());
    let removed_request_id: RequestId = removed_requests.first().unwrap().id().into();
    assert_eq!(removed_request_id, req_3_id);
}

#[tokio::test]
async fn test_active_requests_remove_request() {
    const EXPIRY: Duration = Duration::from_secs(5);
    let mut active_requests = ActiveRequests::new(EXPIRY);

    let node_1 = create_node();
    let node_2 = create_node();
    let (req_1, req_1_addr) = create_req_call(&node_1);
    let (req_2, req_2_addr) = create_req_call(&node_2);
    let (req_3, req_3_addr) = create_req_call(&node_2);
    let req_1_id = req_1.id().into();
    let req_2_id = req_2.id().into();
    let req_3_id = req_3.id().into();

    active_requests.insert(req_1_addr.clone(), req_1);
    active_requests.insert(req_2_addr.clone(), req_2);
    active_requests.insert(req_3_addr.clone(), req_3);
    active_requests.check_invariant();
    let req_id: RequestId = active_requests
        .remove_request(&req_1_addr, &req_1_id)
        .unwrap()
        .id()
        .into();
    assert_eq!(req_id, req_1_id);
    active_requests.check_invariant();
    let req_id: RequestId = active_requests
        .remove_request(&req_2_addr, &req_2_id)
        .unwrap()
        .id()
        .into();
    assert_eq!(req_id, req_2_id);
    active_requests.check_invariant();
    let req_id: RequestId = active_requests
        .remove_request(&req_3_addr, &req_3_id)
        .unwrap()
        .id()
        .into();
    assert_eq!(req_id, req_3_id);
    active_requests.check_invariant();
    assert!(active_requests
        .remove_request(&req_3_addr, &req_3_id)
        .is_none());
}

#[tokio::test]
async fn test_active_requests_remove_by_nonce() {
    const EXPIRY: Duration = Duration::from_secs(5);
    let mut active_requests = ActiveRequests::new(EXPIRY);

    let node_1 = create_node();
    let node_2 = create_node();
    let (req_1, req_1_addr) = create_req_call(&node_1);
    let (req_2, req_2_addr) = create_req_call(&node_2);
    let (req_3, req_3_addr) = create_req_call(&node_2);
    let req_1_nonce = *req_1.packet().message_nonce();
    let req_2_nonce = *req_2.packet().message_nonce();
    let req_3_nonce = *req_3.packet().message_nonce();

    active_requests.insert(req_1_addr.clone(), req_1);
    active_requests.insert(req_2_addr.clone(), req_2);
    active_requests.insert(req_3_addr.clone(), req_3);
    active_requests.check_invariant();

    let req = active_requests.remove_by_nonce(&req_1_nonce).unwrap();
    assert_eq!(req.0, req_1_addr);
    active_requests.check_invariant();
    let req = active_requests.remove_by_nonce(&req_2_nonce).unwrap();
    assert_eq!(req.0, req_2_addr);
    active_requests.check_invariant();
    let req = active_requests.remove_by_nonce(&req_3_nonce).unwrap();
    assert_eq!(req.0, req_3_addr);
    active_requests.check_invariant();
    let random_nonce = rand::random();
    assert!(active_requests.remove_by_nonce(&random_nonce).is_none());
}

#[tokio::test]
async fn test_self_request_ipv4() {
    init();

    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4")
        .ip4(Ipv4Addr::LOCALHOST)
        .udp4(5004)
        .build(&key)
        .unwrap();
    let listen_config = ListenConfig::Ipv4 {
        ip: enr.ip4().unwrap(),
        port: enr.udp4().unwrap(),
    };
    let config = ConfigBuilder::new(listen_config)
        .enable_packet_filter()
        .build();

    let (_exit_send, send, mut recv) =
        Handler::spawn::<DefaultProtocolId>(arc_rw!(enr.clone()), arc_rw!(key), config)
            .await
            .unwrap();

    // self request (IPv4)
    let _ = send.send(HandlerIn::Request(
        NodeContact::try_from_enr(enr.clone(), IpMode::Ip4).unwrap(),
        Box::new(Request {
            id: RequestId(vec![1]),
            body: RequestBody::Ping { enr_seq: 1 },
        }),
    ));
    let handler_out = recv.recv().await;
    assert_eq!(
        Some(RequestFailed(RequestId(vec![1]), SelfRequest)),
        handler_out
    );
}

#[tokio::test]
async fn test_self_request_ipv6() {
    return_if_ipv6_is_not_supported!();

    init();

    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4")
        .ip6(Ipv6Addr::LOCALHOST)
        .udp6(5005)
        .build(&key)
        .unwrap();
    let listen_config = ListenConfig::Ipv6 {
        ip: enr.ip6().unwrap(),
        port: enr.udp6().unwrap(),
    };
    let config = ConfigBuilder::new(listen_config)
        .enable_packet_filter()
        .build();

    let (_exit_send, send, mut recv) =
        Handler::spawn::<DefaultProtocolId>(arc_rw!(enr.clone()), arc_rw!(key), config)
            .await
            .unwrap();

    // self request (IPv6)
    let _ = send.send(HandlerIn::Request(
        NodeContact::try_from_enr(enr, IpMode::Ip6).unwrap(),
        Box::new(Request {
            id: RequestId(vec![2]),
            body: RequestBody::Ping { enr_seq: 1 },
        }),
    ));
    let handler_out = recv.recv().await;
    assert_eq!(
        Some(RequestFailed(RequestId(vec![2]), SelfRequest)),
        handler_out
    );
}

#[tokio::test]
async fn remove_one_time_session() {
    let config = ConfigBuilder::new(ListenConfig::default()).build();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4")
        .ip4(Ipv4Addr::LOCALHOST)
        .udp4(9000)
        .build(&key)
        .unwrap();
    let (_, _, _, mut handler) = build_handler::<DefaultProtocolId>(enr, key, config).await;

    let enr = {
        let key = CombinedKey::generate_secp256k1();
        EnrBuilder::new("v4")
            .ip4(Ipv4Addr::LOCALHOST)
            .udp4(9000)
            .build(&key)
            .unwrap()
    };
    let node_address = NodeAddress::new("127.0.0.1:9000".parse().unwrap(), enr.node_id());
    let request_id = RequestId::random();
    let session = build_dummy_session();
    handler
        .one_time_sessions
        .insert(node_address.clone(), (request_id.clone(), session));

    let other_request_id = RequestId::random();
    assert!(handler
        .remove_one_time_session(&node_address, &other_request_id)
        .is_none());
    assert_eq!(1, handler.one_time_sessions.len());

    let other_node_address = NodeAddress::new("127.0.0.1:9001".parse().unwrap(), enr.node_id());
    assert!(handler
        .remove_one_time_session(&other_node_address, &request_id)
        .is_none());
    assert_eq!(1, handler.one_time_sessions.len());

    assert!(handler
        .remove_one_time_session(&node_address, &request_id)
        .is_some());
    assert_eq!(0, handler.one_time_sessions.len());
}

// Tests replaying active requests.
//
// In this test, Receiver's session expires and Receiver returns WHOAREYOU.
// Sender then creates a new session and resend active requests.
//
// ```mermaid
// sequenceDiagram
//     participant Sender
//     participant Receiver
//     Note over Sender: Start discv5 server
//     Note over Receiver: Start discv5 server
//
//     Note over Sender,Receiver: Session established
//
//     rect rgb(100, 100, 0)
//     Note over Receiver: ** Session expired **
//     end
//
//     rect rgb(10, 10, 10)
//     Note left of Sender: Sender sends requests <br> **in parallel**.
//     par
//     Sender ->> Receiver: PING(id:2)
//     and
//     Sender -->> Receiver: PING(id:3)
//     and
//     Sender -->> Receiver: PING(id:4)
//     and
//     Sender -->> Receiver: PING(id:5)
//     end
//     end
//
//     Note over Receiver: Send WHOAREYOU<br>since the session has been expired
//     Receiver ->> Sender: WHOAREYOU
//
//     rect rgb(100, 100, 0)
//     Note over Receiver: Drop PING(id:2,3,4,5) request<br>since WHOAREYOU already sent.
//     end
//
//     Note over Sender: New session established with Receiver
//
//     Sender ->> Receiver: Handshake message (id:2)
//
//     Note over Receiver: New session established with Sender
//
//     rect rgb(10, 10, 10)
//     Note left of Sender: Handler::replay_active_requests()
//     Sender ->> Receiver: PING (id:3)
//     Sender ->> Receiver: PING (id:4)
//     Sender ->> Receiver: PING (id:5)
//     end
//
//     Receiver ->> Sender: PONG (id:2)
//     Receiver ->> Sender: PONG (id:3)
//     Receiver ->> Sender: PONG (id:4)
//     Receiver ->> Sender: PONG (id:5)
// ```
#[tokio::test]
async fn test_replay_active_requests() {
    init();
    let sender_port = 5006;
    let receiver_port = 5007;
    let ip = "127.0.0.1".parse().unwrap();
    let key1 = CombinedKey::generate_secp256k1();
    let key2 = CombinedKey::generate_secp256k1();

    let sender_enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(sender_port)
        .build(&key1)
        .unwrap();

    let receiver_enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(receiver_port)
        .build(&key2)
        .unwrap();

    // Build sender handler
    let (sender_exit, sender_send, mut sender_recv, mut handler) = {
        let sender_listen_config = ListenConfig::Ipv4 {
            ip: sender_enr.ip4().unwrap(),
            port: sender_enr.udp4().unwrap(),
        };
        let sender_config = ConfigBuilder::new(sender_listen_config).build();
        build_handler::<DefaultProtocolId>(sender_enr.clone(), key1, sender_config).await
    };
    let sender = async move {
        // Start sender handler.
        handler.start::<DefaultProtocolId>().await;
        // After the handler has been terminated test the handler's states.
        assert!(handler.pending_requests.is_empty());
        assert_eq!(0, handler.active_requests.count().await);
        assert!(handler.active_challenges.is_empty());
        assert!(handler.filter_expected_responses.read().is_empty());
    };

    // Build receiver handler
    // Shorten receiver's timeout to reproduce session expired.
    let receiver_session_timeout = Duration::from_secs(1);
    let (receiver_exit, receiver_send, mut receiver_recv, mut handler) = {
        let receiver_listen_config = ListenConfig::Ipv4 {
            ip: receiver_enr.ip4().unwrap(),
            port: receiver_enr.udp4().unwrap(),
        };
        let receiver_config = ConfigBuilder::new(receiver_listen_config)
            .session_timeout(receiver_session_timeout)
            .build();
        build_handler::<DefaultProtocolId>(receiver_enr.clone(), key2, receiver_config).await
    };
    let receiver = async move {
        // Start receiver handler.
        handler.start::<DefaultProtocolId>().await;
        // After the handler has been terminated test the handler's states.
        assert!(handler.pending_requests.is_empty());
        assert_eq!(0, handler.active_requests.count().await);
        assert!(handler.active_challenges.is_empty());
        assert!(handler.filter_expected_responses.read().is_empty());
    };

    let messages_to_send = 5usize;

    let sender_ops = async move {
        let mut response_count = 0usize;
        let mut expected_request_ids = HashSet::new();
        expected_request_ids.insert(RequestId(vec![1]));

        // sender to send the first message then await for the session to be established
        let _ = sender_send.send(HandlerIn::Request(
            receiver_enr.clone().into(),
            Box::new(Request {
                id: RequestId(vec![1]),
                body: RequestBody::Ping { enr_seq: 1 },
            }),
        ));

        match sender_recv.recv().await {
            Some(HandlerOut::Established(_, _, _)) => {
                // Sleep until receiver's session expired.
                tokio::time::sleep(receiver_session_timeout.add(Duration::from_millis(500))).await;
                // send the rest of the messages
                for req_id in 2..=messages_to_send {
                    let request_id = RequestId(vec![req_id as u8]);
                    expected_request_ids.insert(request_id.clone());
                    let _ = sender_send.send(HandlerIn::Request(
                        receiver_enr.clone().into(),
                        Box::new(Request {
                            id: request_id,
                            body: RequestBody::Ping { enr_seq: 1 },
                        }),
                    ));
                }
            }
            handler_out => panic!("Unexpected message: {:?}", handler_out),
        }

        loop {
            match sender_recv.recv().await {
                Some(HandlerOut::Response(_, response)) => {
                    assert!(expected_request_ids.remove(&response.id));
                    response_count += 1;
                    if response_count == messages_to_send {
                        // Notify the handlers that the message exchange has been completed.
                        assert!(expected_request_ids.is_empty());
                        sender_exit.send(()).unwrap();
                        receiver_exit.send(()).unwrap();
                        return;
                    }
                }
                _ => continue,
            };
        }
    };

    let receiver_ops = async move {
        let mut message_count = 0usize;
        loop {
            match receiver_recv.recv().await {
                Some(HandlerOut::WhoAreYou(wru_ref)) => {
                    receiver_send
                        .send(HandlerIn::WhoAreYou(wru_ref, Some(sender_enr.clone())))
                        .unwrap();
                }
                Some(HandlerOut::Request(addr, request)) => {
                    assert!(matches!(request.body, RequestBody::Ping { .. }));
                    let pong_response = Response {
                        id: request.id,
                        body: ResponseBody::Pong {
                            enr_seq: 1,
                            ip: ip.into(),
                            port: sender_port,
                        },
                    };
                    receiver_send
                        .send(HandlerIn::Response(addr, Box::new(pong_response)))
                        .unwrap();
                    message_count += 1;
                    if message_count == messages_to_send {
                        return;
                    }
                }
                _ => {
                    continue;
                }
            }
        }
    };

    let sleep_future = sleep(Duration::from_secs(5));
    let message_exchange = async move {
        let _ = tokio::join!(sender, sender_ops, receiver, receiver_ops);
    };

    tokio::select! {
        _ = message_exchange => {}
        _ = sleep_future => {
            panic!("Test timed out");
        }
    }
}
