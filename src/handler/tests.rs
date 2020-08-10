#![cfg(test)]
use super::*;
use crate::rpc::{Request, Response};
use crate::{Discv5ConfigBuilder, TokioExecutor};
use enr::EnrBuilder;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::delay_for;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
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
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    let key1 = CombinedKey::generate_secp256k1();
    let key2 = CombinedKey::generate_secp256k1();

    let config = Discv5ConfigBuilder::new()
        .executor(Box::new(TokioExecutor(tokio::runtime::Handle::current())))
        .build();

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

    let (_exit_send, sender_handler, _) = Handler::spawn(
        arc_rw!(sender_enr.clone()),
        arc_rw!(key1),
        sender_enr.udp_socket().unwrap(),
        config.clone(),
    )
    .unwrap();

    let (_exit_recv, recv_send, mut receiver_handler) = Handler::spawn(
        arc_rw!(receiver_enr.clone()),
        arc_rw!(key2),
        receiver_enr.udp_socket().unwrap(),
        config,
    )
    .unwrap();

    let send_message = Box::new(Request {
        id: 1,
        body: RequestBody::Ping { enr_seq: 1 },
    });

    let _ = sender_handler.send(HandlerRequest::Request(
        receiver_enr.into(),
        send_message.clone(),
    ));

    let receiver = async move {
        loop {
            if let Some(message) = receiver_handler.recv().await {
                match message {
                    HandlerResponse::WhoAreYou(wru_ref) => {
                        let _ = recv_send
                            .send(HandlerRequest::WhoAreYou(wru_ref, Some(sender_enr.clone())));
                    }
                    HandlerResponse::Request(_, request) => {
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
        _ = delay_for(Duration::from_millis(100)) => {
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
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let key1 = CombinedKey::generate_secp256k1();
    let key2 = CombinedKey::generate_secp256k1();

    let config = Discv5ConfigBuilder::new()
        .executor(Box::new(TokioExecutor(tokio::runtime::Handle::current())))
        .build();

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

    let (_exit_send, sender_handler, mut sender_handler_recv) = Handler::spawn(
        arc_rw!(sender_enr.clone()),
        arc_rw!(key1),
        sender_enr.udp_socket().unwrap(),
        config.clone(),
    )
    .unwrap();

    let (_exit_recv, recv_send, mut receiver_handler) = Handler::spawn(
        arc_rw!(receiver_enr.clone()),
        arc_rw!(key2),
        receiver_enr.udp_socket().unwrap(),
        config,
    )
    .unwrap();

    let send_message = Box::new(Request {
        id: 1,
        body: RequestBody::Ping { enr_seq: 1 },
    });

    let pong_response = Response {
        id: 1,
        body: ResponseBody::Ping {
            enr_seq: 1,
            ip,
            port: sender_port,
        },
    };

    let messages_to_send = 5usize;

    // sender to send the first message then await for the session to be established
    let _ = sender_handler.send(HandlerRequest::Request(
        receiver_enr.clone().into(),
        send_message.clone(),
    ));

    let mut message_count = 0usize;
    let recv_send_message = send_message.clone();

    let sender = async move {
        loop {
            match sender_handler_recv.next().await {
                Some(HandlerResponse::Established(_)) => {
                    // now the session is established, send the rest of the messages
                    for _ in 0..messages_to_send - 1 {
                        let _ = sender_handler.send(HandlerRequest::Request(
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
            match receiver_handler.next().await {
                Some(HandlerResponse::WhoAreYou(wru_ref)) => {
                    let _ = recv_send
                        .send(HandlerRequest::WhoAreYou(wru_ref, Some(sender_enr.clone())));
                }
                Some(HandlerResponse::Request(addr, request)) => {
                    assert_eq!(request, recv_send_message);
                    message_count += 1;
                    // required to send a pong response to establish the session
                    let _ = recv_send.send(HandlerRequest::Response(
                        addr,
                        Box::new(pong_response.clone()),
                    ));
                    if message_count == messages_to_send {
                        return;
                    }
                }
                _ => continue,
            }
        }
    };

    tokio::select! {
        _ = sender => {}
        _ = receiver => {}
        _ = delay_for(Duration::from_millis(100)) => {
            panic!("Test timed out");
        }
    }
}
