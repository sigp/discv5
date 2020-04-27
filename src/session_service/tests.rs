#![cfg(test)]
use super::*;
use crate::rpc::{Request, Response, RpcType};
use enr::EnrBuilder;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::prelude::*;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
// Tests the construction and sending of a simple message
fn simple_session_message() {
    init();

    let sender_port = 5000;
    let receiver_port = 5001;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    let key1 = CombinedKey::generate_secp256k1();
    let key2 = CombinedKey::generate_secp256k1();

    let config = Discv5Config::default();

    let sender_enr = EnrBuilder::new("v4")
        .ip(ip)
        .udp(sender_port)
        .build(&key1)
        .unwrap();
    let receiver_enr = EnrBuilder::new("v4")
        .ip(ip)
        .udp(receiver_port)
        .build(&key2)
        .unwrap();

    let mut sender_service = SessionService::new(
        sender_enr.clone(),
        key1,
        sender_enr.udp_socket().unwrap(),
        config.clone(),
    )
    .unwrap();
    let mut receiver_service = SessionService::new(
        receiver_enr.clone(),
        key2,
        receiver_enr.udp_socket().unwrap(),
        config,
    )
    .unwrap();

    let send_message = ProtocolMessage {
        id: 1,
        body: RpcType::Request(Request::Ping { enr_seq: 1 }),
    };

    let receiver_send_message = send_message.clone();

    let _ = sender_service.send_request(&receiver_enr, send_message);

    let sender = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            match sender_service.poll() {
                Async::Ready(_) => {}
                Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    let receiver = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            let message = match receiver_service.poll() {
                Async::Ready(message) => message,
                Async::NotReady => return Ok(Async::NotReady),
            };

            match message {
                SessionEvent::WhoAreYouRequest { src, auth_tag, .. } => {
                    let seq = sender_enr.seq();
                    let node_id = &sender_enr.node_id();
                    receiver_service.send_whoareyou(
                        src,
                        node_id,
                        seq,
                        Some(sender_enr.clone()),
                        auth_tag,
                    );
                }
                SessionEvent::Message { message, .. } => {
                    assert_eq!(*message, receiver_send_message);
                    return Ok(Async::Ready(()));
                }
                _ => {}
            }
        }
    });

    let test_result = Arc::new(Mutex::new(true));
    let thread_result = test_result.clone();
    tokio::run(
        sender
            .select(receiver)
            .timeout(Duration::from_millis(100))
            .map_err(move |_| *thread_result.lock().unwrap() = false)
            .map(|_| ()),
    );
    assert!(*test_result.lock().unwrap());
}

#[test]
// Tests sending multiple messages on an encrypted session
fn multiple_messages() {
    init();
    let sender_port = 5002;
    let receiver_port = 5003;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key1 = CombinedKey::generate_secp256k1();
    let key2 = CombinedKey::generate_secp256k1();

    let sender_enr = EnrBuilder::new("v4")
        .ip(ip)
        .udp(sender_port)
        .build(&key1)
        .unwrap();
    let receiver_enr = EnrBuilder::new("v4")
        .ip(ip)
        .udp(receiver_port)
        .build(&key2)
        .unwrap();

    let mut sender_service = SessionService::new(
        sender_enr.clone(),
        key1,
        sender_enr.udp_socket().unwrap(),
        Discv5Config::default(),
    )
    .unwrap();
    let mut receiver_service = SessionService::new(
        receiver_enr.clone(),
        key2,
        receiver_enr.udp_socket().unwrap(),
        Discv5Config::default(),
    )
    .unwrap();

    let send_message = ProtocolMessage {
        id: 1,
        body: RpcType::Request(Request::Ping { enr_seq: 1 }),
    };

    let pong_response = ProtocolMessage {
        id: 1,
        body: RpcType::Response(Response::Ping {
            enr_seq: 1,
            ip,
            port: sender_port,
        }),
    };

    let receiver_send_message = send_message.clone();

    let messages_to_send = 5;

    // sender to send the first message then await for the session to be established
    let _ = sender_service.send_request(&receiver_enr, send_message.clone());

    let mut message_count = 0;

    let sender = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            match sender_service.poll() {
                Async::Ready(SessionEvent::Established(_)) => {
                    // now the session is established, send the rest of the messages
                    for _ in 0..messages_to_send - 1 {
                        let _ = sender_service.send_request(&receiver_enr, send_message.clone());
                    }
                }
                Async::Ready(_) => {}
                Async::NotReady => return Ok(Async::NotReady),
            };
        }
    });

    let receiver = future::poll_fn(move || -> Poll<(), ()> {
        loop {
            let message = match receiver_service.poll() {
                Async::Ready(message) => message,
                Async::NotReady => return Ok(Async::NotReady),
            };

            match message {
                SessionEvent::WhoAreYouRequest { src, auth_tag, .. } => {
                    let seq = sender_enr.seq();
                    let node_id = &sender_enr.node_id();
                    receiver_service.send_whoareyou(
                        src,
                        node_id,
                        seq,
                        Some(sender_enr.clone()),
                        auth_tag,
                    );
                }
                SessionEvent::Message { message, .. } => {
                    assert_eq!(*message, receiver_send_message);
                    message_count += 1;
                    // required to send a pong response to establish the session
                    let _ = receiver_service.send_request(&sender_enr, pong_response.clone());
                    if message_count == messages_to_send {
                        return Ok(Async::Ready(()));
                    }
                }
                _ => {}
            }
        }
    });

    let test_result = Arc::new(Mutex::new(true));
    let thread_result = test_result.clone();
    tokio::run(
        sender
            .select(receiver)
            .timeout(Duration::from_millis(100))
            .map_err(move |_| *thread_result.lock().unwrap() = false)
            .map(|_| ()),
    );
    assert!(*test_result.lock().unwrap());
}
