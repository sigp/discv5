#![cfg(test)]

use super::*;

use crate::{
    handler::Handler,
    kbucket,
    kbucket::{BucketInsertResult, KBucketsTable, NodeStatus},
    node_info::NodeContact,
    query_pool::{QueryId, QueryPool},
    rpc,
    rpc::RequestId,
    service::{ActiveRequest, Service},
    Discv5ConfigBuilder, Enr,
};
use enr::{CombinedKey, EnrBuilder};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
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

async fn build_service(
    local_enr: Arc<RwLock<Enr>>,
    enr_key: Arc<RwLock<CombinedKey>>,
    listen_socket: SocketAddr,
    filters: bool,
) -> Service {
    let config = Discv5ConfigBuilder::new()
        .executor(Box::new(crate::executor::TokioExecutor::default()))
        .build();
    // build the session service
    let (_handler_exit, handler_send, handler_recv) = Handler::spawn(
        local_enr.clone(),
        enr_key.clone(),
        listen_socket,
        config.clone(),
    )
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
    }
}

#[tokio::test]
async fn test_updating_connection_on_ping() {
    init();
    let enr_key1 = CombinedKey::generate_secp256k1();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let enr = EnrBuilder::new("v4")
        .ip(ip)
        .udp(10001)
        .build(&enr_key1)
        .unwrap();
    let ip2: IpAddr = "127.0.0.1".parse().unwrap();
    let enr_key2 = CombinedKey::generate_secp256k1();
    let enr2 = EnrBuilder::new("v4")
        .ip(ip2)
        .udp(10002)
        .build(&enr_key2)
        .unwrap();

    let socket_addr = enr.udp_socket().unwrap();

    let mut service = build_service(
        Arc::new(RwLock::new(enr)),
        Arc::new(RwLock::new(enr_key1)),
        socket_addr,
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
    let response = rpc::Response {
        id: RequestId(vec![1]),
        body: rpc::ResponseBody::Pong {
            enr_seq: 2,
            ip: ip2,
            port: 10002,
        },
    };

    let node_contact = NodeContact::Enr(Box::new(enr2));
    let expected_return_addr = node_contact.node_address().unwrap();

    service.active_requests.insert(
        RequestId(vec![1]),
        ActiveRequest {
            contact: node_contact,
            request_body: rpc::RequestBody::Ping { enr_seq: 2 },
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
