#![cfg(test)]

use super::*;

use crate::{
    handler::Handler,
    kbucket,
    kbucket::{BucketInsertResult, KBucketsTable, NodeStatus},
    node_info::NodeContact,
    packet::{DefaultProtocolId, ProtocolIdentity},
    query_pool::{QueryId, QueryPool},
    rpc::RequestId,
    service::{ActiveRequest, Service},
    socket::ListenConfig,
    Discv5ConfigBuilder, Enr,
};
use enr::{CombinedKey, EnrBuilder};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

fn _connected_state() -> NodeStatus {
    NodeStatus {
        state: ConnectionState::Connected,
        direction: ConnectionDirection::Outgoing,
    }
}

fn disconnected_state() -> NodeStatus {
    NodeStatus {
        state: ConnectionState::Disconnected,
        direction: ConnectionDirection::Outgoing,
    }
}

fn init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

async fn build_service<P: ProtocolIdentity>(
    local_enr: Arc<RwLock<Enr>>,
    enr_key: Arc<RwLock<CombinedKey>>,
    filters: bool,
) -> Service {
    let listen_config = ListenConfig::Ipv4 {
        ip: local_enr.read().ip4().unwrap(),
        port: local_enr.read().udp4().unwrap(),
    };
    let config = Discv5ConfigBuilder::new(listen_config)
        .executor(Box::<crate::executor::TokioExecutor>::default())
        .build();
    // build the session service
    let (_handler_exit, handler_send, handler_recv) =
        Handler::spawn::<P>(local_enr.clone(), enr_key.clone(), config.clone())
            .await
            .unwrap();

    let (table_filter, bucket_filter) = if filters {
        (
            Some(Box::new(kbucket::IpTableFilter) as Box<dyn kbucket::Filter<Enr>>),
            Some(Box::new(kbucket::IpBucketFilter) as Box<dyn kbucket::Filter<Enr>>),
        )
    } else {
        (None, None)
    };

    let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
        local_enr.read().node_id().into(),
        Duration::from_secs(60),
        config.incoming_bucket_limit,
        table_filter,
        bucket_filter,
    )));

    // create the required channels
    let (_discv5_send, discv5_recv) = mpsc::channel(30);
    let (_exit_send, exit) = oneshot::channel();

    Service {
        local_enr,
        enr_key,
        kbuckets,
        queries: QueryPool::new(config.query_timeout),
        active_requests: Default::default(),
        active_nodes_responses: HashMap::new(),
        ip_votes: None,
        handler_send,
        handler_recv,
        handler_exit: Some(_handler_exit),
        peers_to_ping: HashSetDelay::new(config.ping_interval),
        discv5_recv,
        event_stream: None,
        exit,
        config,
        ip_mode: Default::default(),
    }
}

#[tokio::test]
async fn test_updating_connection_on_ping() {
    init();
    let enr_key1 = CombinedKey::generate_secp256k1();
    let ip = "127.0.0.1".parse().unwrap();
    let enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(10001)
        .build(&enr_key1)
        .unwrap();
    let ip2 = "127.0.0.1".parse().unwrap();
    let enr_key2 = CombinedKey::generate_secp256k1();
    let enr2 = EnrBuilder::new("v4")
        .ip4(ip2)
        .udp4(10002)
        .build(&enr_key2)
        .unwrap();

    let mut service = build_service::<DefaultProtocolId>(
        Arc::new(RwLock::new(enr)),
        Arc::new(RwLock::new(enr_key1)),
        false,
    )
    .await;
    // Set up service with one disconnected node
    let key = kbucket::Key::from(enr2.node_id());
    if let kbucket::Entry::Absent(entry) = service.kbuckets.write().entry(&key) {
        match entry.insert(enr2.clone(), disconnected_state()) {
            BucketInsertResult::Inserted => {}
            BucketInsertResult::Full => {
                panic!("Can't be full");
            }
            BucketInsertResult::Pending { .. } => {}
            _ => panic!("Could not be inserted"),
        }
    }

    // Add a fake request
    let response = Response {
        id: RequestId(vec![1]),
        body: ResponseBody::Pong {
            enr_seq: 2,
            ip: ip2.into(),
            port: 10002,
        },
    };

    let node_contact: NodeContact = enr2.into();
    let expected_return_addr = node_contact.node_address();

    service.active_requests.insert(
        RequestId(vec![1]),
        ActiveRequest {
            contact: node_contact,
            request_body: RequestBody::Ping { enr_seq: 2 },
            query_id: Some(QueryId(1)),
            callback: None,
        },
    );

    // Handle the ping and expect the disconnected Node to become connected
    service.handle_rpc_response(expected_return_addr, response);
    let buckets = service.kbuckets.read();
    let node = buckets.iter_ref().next().unwrap();
    assert!(node.status.is_connected())
}

#[tokio::test]
async fn test_connection_direction_on_inject_session_established() {
    init();

    let enr_key1 = CombinedKey::generate_secp256k1();
    let ip = std::net::Ipv4Addr::LOCALHOST;
    let enr = EnrBuilder::new("v4")
        .ip4(ip)
        .udp4(10003)
        .build(&enr_key1)
        .unwrap();

    let enr_key2 = CombinedKey::generate_secp256k1();
    let ip2 = std::net::Ipv4Addr::LOCALHOST;
    let enr2 = EnrBuilder::new("v4")
        .ip4(ip2)
        .udp4(10004)
        .build(&enr_key2)
        .unwrap();

    let mut service = build_service::<DefaultProtocolId>(
        Arc::new(RwLock::new(enr)),
        Arc::new(RwLock::new(enr_key1)),
        false,
    )
    .await;

    let key = &kbucket::Key::from(enr2.node_id());

    // Test that the existing connection direction is not updated.
    // Incoming
    service.inject_session_established(enr2.clone(), ConnectionDirection::Incoming);
    let status = service.kbuckets.read().iter_ref().next().unwrap().status;
    assert!(status.is_connected());
    assert_eq!(ConnectionDirection::Incoming, status.direction);

    service.inject_session_established(enr2.clone(), ConnectionDirection::Outgoing);
    let status = service.kbuckets.read().iter_ref().next().unwrap().status;
    assert!(status.is_connected());
    assert_eq!(ConnectionDirection::Incoming, status.direction);

    // (disconnected) Outgoing
    let result = service.kbuckets.write().update_node_status(
        key,
        ConnectionState::Disconnected,
        Some(ConnectionDirection::Outgoing),
    );
    assert!(matches!(result, UpdateResult::Updated));
    service.inject_session_established(enr2.clone(), ConnectionDirection::Incoming);
    let status = service.kbuckets.read().iter_ref().next().unwrap().status;
    assert!(status.is_connected());
    assert_eq!(ConnectionDirection::Outgoing, status.direction);
}
