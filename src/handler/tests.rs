#![cfg(test)]

use super::*;
use crate::{
    handler::sessions::session::build_dummy_session,
    packet::{DefaultProtocolId, PacketHeader, MAX_PACKET_SIZE},
    return_if_ipv6_is_not_supported,
    rpc::{Request, Response},
    Discv5ConfigBuilder, IpMode,
};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{handler::HandlerOut::RequestFailed, RequestError::SelfRequest};
use active_requests::ActiveRequests;
use enr::EnrBuilder;
use std::time::Duration;
use tokio::{net::UdpSocket, time::sleep};

fn init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

struct MockService {
    tx: mpsc::UnboundedSender<HandlerIn>,
    rx: mpsc::Receiver<HandlerOut>,
    exit_tx: oneshot::Sender<()>,
}

async fn build_handler<P: ProtocolIdentity>() -> (Handler, MockService) {
    build_handler_with_listen_config::<P>(ListenConfig::default()).await
}

async fn build_handler_with_listen_config<P: ProtocolIdentity>(
    listen_config: ListenConfig,
) -> (Handler, MockService) {
    let listen_port = listen_config
        .ipv4_port()
        .expect("listen config should default to ipv4");
    let config = Discv5ConfigBuilder::new(listen_config).build();
    let key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4")
        .ip4(Ipv4Addr::LOCALHOST)
        .udp4(listen_port)
        .build(&key)
        .unwrap();
    let mut listen_sockets = SmallVec::default();
    listen_sockets.push((Ipv4Addr::LOCALHOST, listen_port).into());
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
    let (handler_sender, service_recv) = mpsc::unbounded_channel();
    let (service_send, handler_recv) = mpsc::channel(50);
    let (exit_tx, exit) = oneshot::channel();

    let nat_hole_puncher = NatHolePunchUtils::new(
        listen_sockets.iter(),
        &enr,
        config.listen_config.ip_mode(),
        None,
        None,
        config.session_cache_capacity,
    );

    (
        Handler {
            request_retries: config.request_retries,
            node_id,
            enr: Arc::new(RwLock::new(enr)),
            key: Arc::new(RwLock::new(key)),
            active_requests: ActiveRequests::new(config.request_timeout),
            pending_requests: HashMap::new(),
            filter_expected_responses,
            sessions: Sessions::new(config.session_cache_capacity, config.session_timeout, None),
            one_time_sessions: LruTimeCache::new(
                Duration::from_secs(ONE_TIME_SESSION_TIMEOUT),
                Some(ONE_TIME_SESSION_CACHE_CAPACITY),
            ),
            active_challenges: HashMapDelay::new(config.request_timeout),
            service_recv,
            service_send,
            listen_sockets,
            socket,
            nat_hole_puncher,
            exit,
        },
        MockService {
            tx: handler_sender,
            rx: handler_recv,
            exit_tx,
        },
    )
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
    let sender_config = Discv5ConfigBuilder::new(sender_listen_config)
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
    let receiver_config = Discv5ConfigBuilder::new(receiver_listen_config)
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
    let sender_listen_config = ListenConfig::Ipv4 {
        ip: sender_enr.ip4().unwrap(),
        port: sender_enr.udp4().unwrap(),
    };
    let sender_config = Discv5ConfigBuilder::new(sender_listen_config).build();

    let receiver_enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(receiver_port)
        .build(&key2)
        .unwrap();
    let receiver_listen_config = ListenConfig::Ipv4 {
        ip: receiver_enr.ip4().unwrap(),
        port: receiver_enr.udp4().unwrap(),
    };
    let receiver_config = Discv5ConfigBuilder::new(receiver_listen_config).build();

    let (_exit_send, sender_handler, mut sender_handler_recv) =
        Handler::spawn::<DefaultProtocolId>(
            arc_rw!(sender_enr.clone()),
            arc_rw!(key1),
            sender_config,
        )
        .await
        .unwrap();

    let (_exit_recv, recv_send, mut receiver_handler) = Handler::spawn::<DefaultProtocolId>(
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

    // sender to send the first message then await for the session to be established
    let _ = sender_handler.send(HandlerIn::Request(
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

    let sender = async move {
        loop {
            match sender_handler_recv.recv().await {
                Some(HandlerOut::Established(_, _, _)) => {
                    // now the session is established, send the rest of the messages
                    for _ in 0..messages_to_send - 1 {
                        let _ = sender_handler.send(HandlerIn::Request(
                            receiver_enr.clone().into(),
                            send_message.clone(),
                        ));
                    }
                }
                _ => continue,
            };
        }
    };

    let receiver = async move {
        loop {
            match receiver_handler.recv().await {
                Some(HandlerOut::WhoAreYou(wru_ref)) => {
                    let _ = recv_send.send(HandlerIn::WhoAreYou(wru_ref, Some(sender_enr.clone())));
                }
                Some(HandlerOut::Request(addr, request)) => {
                    assert_eq!(request, recv_send_message);
                    message_count += 1;
                    // required to send a pong response to establish the session
                    let _ =
                        recv_send.send(HandlerIn::Response(addr, Box::new(pong_response.clone())));
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

    tokio::select! {
        _ = sender => {}
        _ = receiver => {}
        _ = sleep_future => {
            panic!("Test timed out");
        }
    }
}

#[tokio::test]
async fn test_active_requests_insert() {
    const EXPIRY: Duration = Duration::from_secs(5);
    let mut active_requests = ActiveRequests::new(EXPIRY);

    // Create the test values needed
    let port = 5000;
    let ip = "127.0.0.1".parse().unwrap();

    let key = CombinedKey::generate_secp256k1();

    let enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(port)
        .build(&key)
        .unwrap();
    let node_id = enr.node_id();

    let contact: NodeContact = enr.into();
    let node_address = contact.node_address();

    let packet = Packet::new_random(&node_id).unwrap();
    let id = HandlerReqId::Internal(RequestId::random());
    let request = RequestBody::Ping { enr_seq: 1 };
    let initiating_session = true;
    let request_call = RequestCall::new(contact, packet, id, request, initiating_session);

    // insert the pair and verify the mapping remains in sync
    let nonce = *request_call.packet().message_nonce();
    active_requests.insert(node_address, request_call);
    active_requests.check_invariant();
    active_requests.remove_by_nonce(&nonce);
    active_requests.check_invariant();
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
    let config = Discv5ConfigBuilder::new(listen_config)
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
    let config = Discv5ConfigBuilder::new(listen_config)
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
    let (mut handler, _) = build_handler::<DefaultProtocolId>().await;

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

#[tokio::test(flavor = "multi_thread")]
async fn relay() {
    init();

    // Relay
    let listen_config = ListenConfig::default().with_ipv4(Ipv4Addr::LOCALHOST, 9901);
    let (mut handler, mock_service) =
        build_handler_with_listen_config::<DefaultProtocolId>(listen_config).await;
    let relay_addr = handler.enr.read().udp4_socket().unwrap().into();
    let relay_node_id = handler.enr.read().node_id();
    let mut dummy_session = build_dummy_session();

    // Initiator
    let initr_enr = {
        let key = CombinedKey::generate_secp256k1();
        EnrBuilder::new("v4")
            .ip4(Ipv4Addr::LOCALHOST)
            .udp4(9011)
            .build(&key)
            .unwrap()
    };
    let initr_addr = initr_enr.udp4_socket().unwrap().into();
    let initr_node_id = initr_enr.node_id();

    let initr_node_address = NodeAddress::new(initr_addr, initr_enr.node_id());
    handler
        .sessions
        .cache
        .insert(initr_node_address, dummy_session.clone());

    let initr_socket = UdpSocket::bind(initr_addr)
        .await
        .expect("should bind to initiator socket");

    // Target
    let tgt_enr = {
        let key = CombinedKey::generate_secp256k1();
        EnrBuilder::new("v4")
            .ip4(Ipv4Addr::LOCALHOST)
            .udp4(9012)
            .build(&key)
            .unwrap()
    };
    let tgt_addr = tgt_enr.udp4_socket().unwrap().into();
    let tgt_node_id = tgt_enr.node_id();

    let tgt_node_address = NodeAddress::new(tgt_addr, tgt_enr.node_id());
    handler
        .sessions
        .cache
        .insert(tgt_node_address, dummy_session.clone());

    let tgt_socket = UdpSocket::bind(tgt_addr)
        .await
        .expect("should bind to target socket");

    // Relay handle
    let relay_handle = tokio::spawn(async move { handler.start::<DefaultProtocolId>().await });

    // Relay mock service
    let tgt_enr_clone = tgt_enr.clone();
    let tx = mock_service.tx;
    let mut rx = mock_service.rx;
    let mock_service_handle = tokio::spawn(async move {
        let service_msg = rx.recv().await.expect("should receive service message");
        match service_msg {
            HandlerOut::FindHolePunchEnr(_tgt_node_id, relay_msg_notif) => tx
                .send(HandlerIn::HolePunchEnr(tgt_enr_clone, relay_msg_notif))
                .expect("should send message to handler"),
            _ => panic!("service message should be 'find hole punch enr'"),
        }
    });

    // Initiator handle
    let relay_init_notif =
        Notification::RelayInit(initr_enr.clone(), tgt_node_id, MessageNonce::default());

    let initr_handle = tokio::spawn(async move {
        let mut session = build_dummy_session();
        let packet = session
            .encrypt_session_message::<DefaultProtocolId>(initr_node_id, &relay_init_notif.encode())
            .expect("should encrypt notification");
        let encoded_packet = packet.encode::<DefaultProtocolId>(&relay_node_id);

        initr_socket
            .send_to(&encoded_packet, relay_addr)
            .await
            .expect("should relay init notification to relay")
    });

    // Target handle
    let relay_exit = mock_service.exit_tx;
    let tgt_handle = tokio::spawn(async move {
        let mut buffer = [0; MAX_PACKET_SIZE];
        let res = tgt_socket
            .recv_from(&mut buffer)
            .await
            .expect("should read bytes from socket");

        drop(relay_exit);

        (res, buffer)
    });

    // Join all handles
    let (initr_res, relay_res, tgt_res, mock_service_res) =
        tokio::join!(initr_handle, relay_handle, tgt_handle, mock_service_handle);

    initr_res.unwrap();
    relay_res.unwrap();
    mock_service_res.unwrap();

    let ((length, src), buffer) = tgt_res.unwrap();

    assert_eq!(src, relay_addr);

    let (packet, aad) = Packet::decode::<DefaultProtocolId>(&tgt_enr.node_id(), &buffer[..length])
        .expect("should decode packet");
    let Packet {
        header, message, ..
    } = packet;
    let PacketHeader {
        kind,
        message_nonce,
        ..
    } = header;

    assert_eq!(
        PacketKind::SessionMessage {
            src_id: relay_node_id
        },
        kind
    );

    let decrypted_message = dummy_session
        .decrypt_message(message_nonce, &message, &aad)
        .expect("should decrypt message");
    match Message::decode(&decrypted_message).expect("should decode message") {
        Message::Notification(Notification::RelayMsg(enr, _nonce)) => {
            assert_eq!(initr_enr, enr)
        }
        _ => panic!("message should decode to a relay msg notification"),
    }
}
