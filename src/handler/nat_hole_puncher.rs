use crate::{
    handler::{Handler, HandlerOut, WhoAreYouRef},
    node_info::{NodeAddress, NodeContact},
    packet::MessageNonce,
    rpc::{Notification, Payload},
    Discv5Error, Enr, IpMode, ProtocolIdentity,
};
use delay_map::HashSetDelay;
use enr::NodeId;
use futures::{Stream, StreamExt};
use rand::Rng;
use std::{
    collections::HashMap,
    fmt::Debug,
    net::{IpAddr, SocketAddr, UdpSocket},
    ops::RangeInclusive,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use thiserror::Error;
use tracing::{trace, warn};

/// The expected shortest lifetime in most NAT configurations of a punched hole in seconds.
pub const DEFAULT_HOLE_PUNCH_LIFETIME: u64 = 20;
/// The default number of ports to try before concluding that the local node is behind NAT.
pub const PORT_BIND_TRIES: usize = 4;
/// Port range that is not impossible to bind to.
pub const USER_AND_DYNAMIC_PORTS: RangeInclusive<u16> = 1025..=u16::MAX;

/// An error occurred whilst attempting to hole punch NAT.
#[derive(Debug, Error)]
pub enum Error {
    #[error("NAT error, failed as initiator of a hole punch attempt, {0}")]
    Initiator(Discv5Error),
    #[error("NAT error, failed as relay of a hole punch attempt, {0}")]
    Relay(Discv5Error),
    #[error("NAT error, failed as target of a hole punch attempt, {0}")]
    Target(Discv5Error),
}

/// A request times out. Should trigger the initiation of a hole punch attempt, given a
/// transitive route to the target exists.
pub async fn on_request_time_out<P: ProtocolIdentity>(
    handler: &mut Handler<P>,
    relay: NodeAddress,
    local_enr: Enr, // initiator-enr
    timed_out_nonce: MessageNonce,
    target_session_index: NodeAddress,
) -> Result<(), Error> {
    // Another hole punch process with this target may have just completed.
    if handler.sessions.cache.get(&target_session_index).is_some() {
        return Ok(());
    }
    if let Some(session) = handler.sessions.cache.get_mut(&relay) {
        let relay_init_notif =
            Notification::RelayInit(local_enr, target_session_index.node_id, timed_out_nonce);
        trace!(
            "Sending notif to relay {}. relay init: {}",
            relay.node_id,
            relay_init_notif,
        );
        // Encrypt the message and send
        let packet =
            match session.encrypt_notification::<P>(handler.node_id, &relay_init_notif.encode()) {
                Ok(packet) => packet,
                Err(e) => {
                    return Err(Error::Initiator(e));
                }
            };
        handler.send(relay, packet).await;
    } else {
        // Drop hole punch attempt with this relay, to ensure hole punch round-trip time stays
        // within the time out of the udp entrypoint for the target peer in the initiator's
        // router, set by the original timed out FINDNODE request from the initiator, as the
        // initiator may also be behind a NAT.
        warn!(
            "Session is not established. Dropping relay notification for relay: {}",
            relay.node_id
        );
    }
    Ok(())
}

/// A RelayInit notification is received over discv5 indicating this node is the relay. Should
/// trigger sending a RelayMsg to the target.
pub async fn on_relay_init<P: ProtocolIdentity>(
    handler: &mut Handler<P>,
    initr: Enr,
    tgt: NodeId,
    timed_out_nonce: MessageNonce,
) -> Result<(), Error> {
    // Assemble the notification for the target
    let relay_msg_notif = Notification::RelayMsg(initr, timed_out_nonce);

    // Check for target peer in our kbuckets otherwise drop notification.
    if let Err(e) = handler
        .service_send
        .send(HandlerOut::FindHolePunchEnr(tgt, relay_msg_notif))
        .await
    {
        return Err(Error::Relay(e.into()));
    }
    Ok(())
}

/// A RelayMsg notification is received over discv5 indicating this node is the target. Should
/// trigger a WHOAREYOU to be sent to the initiator using the `nonce` in the RelayMsg.
pub async fn on_relay_msg<P: ProtocolIdentity>(
    handler: &mut Handler<P>,
    initr: Enr,
    timed_out_nonce: MessageNonce,
) -> Result<(), Error> {
    let initiator_node_address =
        match NodeContact::try_from_enr(initr, handler.nat_hole_puncher.ip_mode) {
            Ok(contact) => contact.node_address(),
            Err(e) => return Err(Error::Target(e.into())),
        };

    // A session may already have been established.
    if handler
        .sessions
        .cache
        .get(&initiator_node_address)
        .is_some()
    {
        trace!(
            "Session already established with initiator: {}",
            initiator_node_address
        );
        return Ok(());
    }
    // Possibly, an attempt to punch this hole, using another relay, is in progress.
    if handler
        .active_challenges
        .get(&initiator_node_address)
        .is_some()
    {
        trace!(
            "WHOAREYOU packet already sent to initiator: {}",
            initiator_node_address
        );
        return Ok(());
    }
    // If not hole punch attempts are in progress, spawn a WHOAREYOU event to punch a hole in
    // our NAT for initiator.
    let whoareyou_ref = WhoAreYouRef(initiator_node_address, timed_out_nonce);
    if let Err(e) = handler
        .service_send
        .send(HandlerOut::WhoAreYou(whoareyou_ref))
        .await
    {
        return Err(Error::Target(e.into()));
    }
    Ok(())
}

pub async fn send_relay_msg_notif<P: ProtocolIdentity>(
    handler: &mut Handler<P>,
    tgt_enr: Enr,
    relay_msg_notif: Notification,
) -> Result<(), Error> {
    let tgt_node_address =
        match NodeContact::try_from_enr(tgt_enr, handler.nat_hole_puncher.ip_mode) {
            Ok(contact) => contact.node_address(),
            Err(e) => return Err(Error::Relay(e.into())),
        };
    if let Some(session) = handler.sessions.cache.get_mut(&tgt_node_address) {
        trace!(
            "Sending notif to target {}. relay msg: {}",
            tgt_node_address.node_id,
            relay_msg_notif,
        );
        // Encrypt the notification and send
        let packet =
            match session.encrypt_notification::<P>(handler.node_id, &relay_msg_notif.encode()) {
                Ok(packet) => packet,
                Err(e) => {
                    return Err(Error::Relay(e));
                }
            };
        handler.send(tgt_node_address, packet).await;
        Ok(())
    } else {
        // Either the session is being established or has expired. We simply drop the
        // notification in this case to ensure hole punch round-trip time stays within the
        // time out of the udp entrypoint for the target peer in the initiator's NAT, set by
        // the original timed out FINDNODE request from the initiator, as the initiator may
        // also be behind a NAT.
        Err(Error::Relay(Discv5Error::SessionNotEstablished))
    }
}

/// A punched hole closes. Should trigger an empty packet to be sent to the peer.
pub async fn on_hole_punch_expired<P: ProtocolIdentity>(
    handler: &mut Handler<P>,
    dst: SocketAddr,
) -> Result<(), Error> {
    handler.send_outbound(dst.into()).await;
    Ok(())
}

/// Types necessary to implement nat hole punching for [`Handler`].
pub(crate) struct NatHolePunchUtils {
    /// Ip mode as set in config.
    pub ip_mode: IpMode,
    /// This node has been observed to be behind a NAT.
    pub is_behind_nat: Option<bool>,
    /// The last peer to send us a new peer in a NODES response is stored as the new peer's
    /// potential relay until the first request to the new peer after its discovery is either
    /// responded or failed.
    pub new_peer_latest_relay: HashMap<NodeId, NodeAddress>,
    /// Keeps track if this node needs to send a packet to a peer in order to keep a hole punched
    /// for it in its NAT.
    pub hole_punch_tracker: HashSetDelay<SocketAddr>,
    /// Ports to trie to bind to check if this node is behind NAT.
    pub unused_port_range: Option<RangeInclusive<u16>>,
}

impl NatHolePunchUtils {
    pub(crate) fn new(
        listen_port: u16,
        local_enr: &Enr,
        ip_mode: IpMode,
        unused_port_range: Option<RangeInclusive<u16>>,
    ) -> Self {
        let mut nat_hole_puncher = NatHolePunchUtils {
            ip_mode,
            is_behind_nat: None,
            new_peer_latest_relay: Default::default(),
            hole_punch_tracker: HashSetDelay::new(Duration::from_secs(DEFAULT_HOLE_PUNCH_LIFETIME)),
            unused_port_range,
        };
        // Optimistically only test one advertised socket, ipv4 has precedence. If it is
        // reachable, assumption is made that also the other ip version socket is reachable.
        match (
            local_enr.ip4(),
            local_enr.udp4(),
            local_enr.ip6(),
            local_enr.udp6(),
        ) {
            (Some(ip), port, _, _) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, Some(ip.into()), port);
            }
            (_, _, Some(ip6), port) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, Some(ip6.into()), port);
            }
            (None, Some(port), _, _) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, None, Some(port));
            }
            (_, _, None, Some(port)) => {
                nat_hole_puncher.set_is_behind_nat(listen_port, None, Some(port));
            }
            (None, None, None, None) => {}
        }
        nat_hole_puncher
    }

    pub(crate) fn track(&mut self, peer_socket: SocketAddr) {
        if self.is_behind_nat == Some(false) {
            return;
        }
        self.hole_punch_tracker.insert(peer_socket);
    }

    /// Called when a new observed address is reported at start up or after a
    /// [`crate::Discv5Event::SocketUpdated`].
    pub(crate) fn set_is_behind_nat(
        &mut self,
        listen_port: u16,
        observed_ip: Option<IpAddr>,
        observed_port: Option<u16>,
    ) {
        if Some(listen_port) != observed_port {
            self.is_behind_nat = Some(true);
            return;
        }
        // Without and observed IP it is too early to conclude if the local node is behind a NAT,
        // return.
        let Some(ip) = observed_ip else {
            return;
        };
        self.is_behind_nat = Some(is_behind_nat(ip, &self.unused_port_range));
    }
}

impl Stream for NatHolePunchUtils {
    type Item = Result<SocketAddr, String>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Until ip voting is done and an observed public address is finalised, all nodes act as
        // if they are behind a NAT.
        if self.is_behind_nat == Some(false) || self.hole_punch_tracker.is_empty() {
            return Poll::Pending;
        }
        self.hole_punch_tracker.poll_next_unpin(cx)
    }
}

/// Helper function to test if the local node is behind NAT based on the node's observed reachable
/// socket.
pub fn is_behind_nat(observed_ip: IpAddr, unused_port_range: &Option<RangeInclusive<u16>>) -> bool {
    // If the node cannot bind to the observed address at any of some random ports, we
    // conclude it is behind NAT.
    let mut rng = rand::thread_rng();
    let unused_port_range = match unused_port_range {
        Some(range) => range,
        None => &USER_AND_DYNAMIC_PORTS,
    };
    for _ in 0..PORT_BIND_TRIES {
        let rnd_port: u16 = rng.gen_range(unused_port_range.clone());
        if UdpSocket::bind((observed_ip, rnd_port)).is_ok() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_not_behind_nat() {
        assert!(!is_behind_nat(IpAddr::from([127, 0, 0, 1]), &None));
    }

    #[test]
    fn test_is_behind_nat() {
        assert!(is_behind_nat(IpAddr::from([8, 8, 8, 8]), &None));
    }

    #[test]
    fn test_is_not_behind_nat_ipv6() {
        assert!(!is_behind_nat(
            IpAddr::from([0u16, 0u16, 0u16, 0u16, 0u16, 0u16, 0u16, 1u16]),
            &None,
        ));
    }

    #[test]
    fn test_is_behind_nat_ipv6() {
        // google's ipv6
        assert!(is_behind_nat(
            IpAddr::from([2001, 4860, 4860, 0u16, 0u16, 0u16, 0u16, 0u16]),
            &None,
        ));
    }
}
