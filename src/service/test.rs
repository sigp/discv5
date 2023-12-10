#![cfg(test)]

use super::*;

use crate::{
    discv5::test::generate_deterministic_keypair,
    handler::Handler,
    kbucket,
    kbucket::{BucketInsertResult, KBucketsTable, NodeStatus},
    node_info::NodeContact,
    packet::{DefaultProtocolId, ProtocolIdentity},
    query_pool::{QueryId, QueryPool},
    rpc::RequestId,
    service::{ActiveRequest, Service},
    socket::ListenConfig,
    ConfigBuilder, Enr,
};
use enr::CombinedKey;
use parking_lot::RwLock;
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

/// Default UDP port number to use for tests requiring UDP exposure
pub const DEFAULT_UDP_PORT: u16 = 0;

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
    let config = ConfigBuilder::new(listen_config)
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
    let enr = Enr::builder()
        .ip4(ip)
        .udp4(DEFAULT_UDP_PORT)
        .build(&enr_key1)
        .unwrap();
    let ip2 = "127.0.0.1".parse().unwrap();
    let enr_key2 = CombinedKey::generate_secp256k1();
    let enr2 = Enr::builder()
        .ip4(ip2)
        .udp4(DEFAULT_UDP_PORT)
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
            port: 9000.try_into().unwrap(),
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
    let enr = Enr::builder()
        .ip4(ip)
        .udp4(DEFAULT_UDP_PORT)
        .build(&enr_key1)
        .unwrap();

    let enr_key2 = CombinedKey::generate_secp256k1();
    let ip2 = std::net::Ipv4Addr::LOCALHOST;
    let enr2 = Enr::builder()
        .ip4(ip2)
        .udp4(DEFAULT_UDP_PORT)
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

#[tokio::test]
async fn test_handling_concurrent_responses() {
    init();

    // Seed is chosen such that all nodes are in the 256th distance of the first node.
    let seed = 1652;
    let mut keypairs = generate_deterministic_keypair(5, seed);

    let mut service = {
        let enr_key = keypairs.pop().unwrap();
        let enr = Enr::builder()
            .ip4(Ipv4Addr::LOCALHOST)
            .udp4(10005)
            .build(&enr_key)
            .unwrap();
        build_service::<DefaultProtocolId>(
            Arc::new(RwLock::new(enr)),
            Arc::new(RwLock::new(enr_key)),
            false,
        )
        .await
    };

    let node_contact: NodeContact = Enr::builder()
        .ip4(Ipv4Addr::LOCALHOST)
        .udp4(10006)
        .build(&keypairs.remove(0))
        .unwrap()
        .into();
    let node_address = node_contact.node_address();

    // Add fake requests
    // Request1
    service.active_requests.insert(
        RequestId(vec![1]),
        ActiveRequest {
            contact: node_contact.clone(),
            request_body: RequestBody::FindNode {
                distances: vec![254, 255, 256],
            },
            query_id: Some(QueryId(1)),
            callback: None,
        },
    );
    // Request2
    service.active_requests.insert(
        RequestId(vec![2]),
        ActiveRequest {
            contact: node_contact,
            request_body: RequestBody::FindNode {
                distances: vec![254, 255, 256],
            },
            query_id: Some(QueryId(2)),
            callback: None,
        },
    );

    assert_eq!(3, keypairs.len());
    let mut enrs_for_response = keypairs
        .iter()
        .enumerate()
        .map(|(i, key)| {
            Enr::builder()
                .ip4(Ipv4Addr::LOCALHOST)
                .udp4(10007 + i as u16)
                .build(key)
                .unwrap()
        })
        .collect::<Vec<_>>();

    // Response to `Request1` is sent as two separate messages in total. Handle the first one of the
    // messages here.
    service.handle_rpc_response(
        node_address.clone(),
        Response {
            id: RequestId(vec![1]),
            body: ResponseBody::Nodes {
                total: 2,
                nodes: vec![enrs_for_response.pop().unwrap()],
            },
        },
    );
    // Service has still two active requests since we are waiting for the second NODE response to
    // `Request1`.
    assert_eq!(2, service.active_requests.len());
    // Service stores the first response to `Request1` into `active_nodes_responses`.
    assert!(!service.active_nodes_responses.is_empty());

    // Second, handle a response to *`Request2`* before the second response to `Request1`.
    service.handle_rpc_response(
        node_address.clone(),
        Response {
            id: RequestId(vec![2]),
            body: ResponseBody::Nodes {
                total: 1,
                nodes: vec![enrs_for_response.pop().unwrap()],
            },
        },
    );
    // `Request2` is completed so now the number of active requests should be one.
    assert_eq!(1, service.active_requests.len());
    // Service still keeps the first response in `active_nodes_responses`.
    assert!(!service.active_nodes_responses.is_empty());

    // Finally, handle the second response to `Request1`.
    service.handle_rpc_response(
        node_address,
        Response {
            id: RequestId(vec![1]),
            body: ResponseBody::Nodes {
                total: 2,
                nodes: vec![enrs_for_response.pop().unwrap()],
            },
        },
    );
    assert!(service.active_requests.is_empty());
    assert!(service.active_nodes_responses.is_empty());
}
