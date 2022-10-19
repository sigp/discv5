#![cfg(test)]
use super::*;
use crate::{
    rpc::{Request, Response},
    Discv5ConfigBuilder,
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

    let config = Discv5ConfigBuilder::new().enable_packet_filter().build();

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

    let hole_punch_pings = Arc::new(RwLock::new(HashSet::default()));

    let (_exit_send, sender_send, _sender_recv) = Handler::spawn(
        arc_rw!(sender_enr.clone()),
        arc_rw!(key1),
        hole_punch_pings,
        sender_enr.udp4_socket().unwrap().into(),
        config.clone(),
    )
    .await
    .unwrap();

    let hole_punch_pings = Arc::new(RwLock::new(HashSet::default()));

    let (_exit_recv, recv_send, mut receiver_recv) = Handler::spawn(
        arc_rw!(receiver_enr.clone()),
        arc_rw!(key2),
        hole_punch_pings,
        receiver_enr.udp4_socket().unwrap().into(),
        config,
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

    let config = Discv5ConfigBuilder::new().build();
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

    let hole_punch_pings = Arc::new(RwLock::new(HashSet::default()));

    let (_exit_send, sender_handler, mut sender_handler_recv) = Handler::spawn(
        arc_rw!(sender_enr.clone()),
        arc_rw!(key1),
        hole_punch_pings,
        sender_enr.udp4_socket().unwrap().into(),
        config.clone(),
    )
    .await
    .unwrap();

    let hole_punch_pings = Arc::new(RwLock::new(HashSet::default()));

    let (_exit_recv, recv_send, mut receiver_handler) = Handler::spawn(
        arc_rw!(receiver_enr.clone()),
        arc_rw!(key2),
        hole_punch_pings,
        receiver_enr.udp4_socket().unwrap().into(),
        config,
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
                Some(HandlerOut::Established(_)) => {
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
    let mut active_requests = ActiveRequests::new(EXPIRY, 1);

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
    let request = Request {
        id: RequestId(vec![1]),
        body: RequestBody::Ping { enr_seq: 1 },
    };
    let initiating_session = true;
    let request_call = RequestCall::new(contact, packet, request, initiating_session, false);

    // insert the pair and verify the mapping remains in sync
    let nonce = *request_call.packet.message_nonce();
    active_requests.insert(node_address, request_call, &node_id);
    active_requests.check_invariant();
    active_requests.remove_by_nonce(&nonce);
    active_requests.check_invariant();
}
