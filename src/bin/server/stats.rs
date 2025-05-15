use discv5::{ConnectionDirection, ConnectionState, Discv5, Event};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Prints discv5 server stats on a regular cadence.
pub fn run(discv5: Arc<Discv5>, break_time: Option<Duration>, stats: u64) {
    let break_time = break_time.unwrap_or_else(|| Duration::from_secs(2));
    tokio::spawn(async move {
        let mut event_stream = discv5.event_stream().await.unwrap();
        let mut stats_interval = tokio::time::interval(break_time);
        let mut ipv6_connections = 0;
        let mut ipv4_connections = 0;
        loop {
            tokio::select! {
                _ = stats_interval.tick() => {
                print_global_stats(Arc::clone(&discv5), ipv6_connections, ipv4_connections);
                print_bucket_stats(Arc::clone(&discv5), stats);
                }
                Some(event) = event_stream.recv() => {
                        match event {
                      Event::SessionEstablished(_enr,addr) => {
                    if addr.is_ipv6() {
                        ipv6_connections += 1;
                    } else if addr.is_ipv4() {
                        ipv4_connections +=1;
                    }
                }
                _ => {}
                }
            }
            }
        }
    });
}

/// A bucket statistic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BucketStatistic {
    /// The associated bucket number.
    pub bucket: u64,
    /// Connected Peer Count
    pub connected_peers: u64,
    /// Disconnected Peer Count
    pub disconnected_peers: u64,
    /// Incoming Peer Count
    pub incoming_peers: u64,
    /// Outgoing Peer Count
    pub outgoing_peers: u64,
    /// The number of ipv6 nodes
    pub ipv6_peers: u64,
}

/// Prints discv5 global statistics
fn print_global_stats(discv5: Arc<Discv5>, ipv6_connections: u64, ipv4_connections: u64) {
    info!("Peers in routing table: {}", discv5.connected_peers());
    info!(
        "Sessions historically established, ipv4: {}, ipv6: {}",
        ipv4_connections, ipv6_connections
    );
}

/// Prints discv5 server stats.
pub fn print_bucket_stats(discv5: Arc<Discv5>, stats: u64) {
    let table_entries = discv5.table_entries();
    let self_id: discv5::Key<_> = discv5.local_enr().node_id().into();

    let mut bucket_values = HashMap::new();

    // Reconstruct the buckets
    for (node_id, enr, status) in table_entries {
        let key: discv5::Key<_> = node_id.into();
        let bucket_no = key.log2_distance(&self_id);
        if let Some(bucket_no) = bucket_no {
            bucket_values
                .entry(bucket_no)
                .or_insert_with(Vec::new)
                .push((enr, status));
        }
    }

    // Build some stats
    let mut bucket_stats = Vec::<BucketStatistic>::new();
    for (bucket, entries) in bucket_values {
        let mut connected_peers = 0;
        let mut connected_incoming_peers = 0;
        let mut connected_outgoing_peers = 0;
        let mut disconnected_peers = 0;
        let mut ipv6_peers = 0;

        for (enr, status) in entries {
            match (status.state, status.direction) {
                (ConnectionState::Connected, ConnectionDirection::Incoming) => {
                    connected_peers += 1;
                    connected_incoming_peers += 1;
                }
                (ConnectionState::Connected, ConnectionDirection::Outgoing) => {
                    connected_peers += 1;
                    connected_outgoing_peers += 1;
                }
                (ConnectionState::Disconnected, _) => {
                    disconnected_peers += 1;
                }
            }
            if matches!(status.state, ConnectionState::Connected) && enr.udp6_socket().is_some() {
                ipv6_peers += 1;
            }
        }

        bucket_stats.push(BucketStatistic {
            bucket,
            connected_peers,
            disconnected_peers,
            incoming_peers: connected_incoming_peers,
            outgoing_peers: connected_outgoing_peers,
            ipv6_peers,
        });
    }

    // Sort the buckets
    bucket_stats.sort_by_key(|stat| stat.connected_peers);

    // Print only the top `stats` number of buckets
    for bucket_stat in bucket_stats.iter().take(stats as usize) {
        let BucketStatistic {
            bucket,
            connected_peers,
            disconnected_peers,
            incoming_peers: connected_incoming_peers,
            outgoing_peers: connected_outgoing_peers,
            ipv6_peers,
        } = bucket_stat;
        info!(
            "Bucket {} statistics: Connected peers: {} (Incoming: {}, Outgoing: {}, ipv6: {}), Disconnected Peers: {}",
            bucket,
            connected_peers,
            connected_incoming_peers,
            connected_outgoing_peers,
            ipv6_peers,
            disconnected_peers
        );
    }
}
