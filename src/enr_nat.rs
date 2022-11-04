//! Provides an extension for ENRs to implement extended NAT-based functions.
use crate::Enr;
use enr::{CombinedKey, EnrError};
use tracing::{trace, warn};

/// Discv5 features.
pub enum Feature {
    /// The protocol for NAT traversal using UDP hole-punching is supported
    /// by this node.
    Nat = 1,
}
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub trait EnrNat<K> {
    const ENR_KEY_FEATURES: &'static str = "features";
    const ENR_KEY_NAT: &'static str = "nat";
    const ENR_KEY_NAT_6: &'static str = "nat6";
    const ENR_KEY_IP: &'static str = "ip";
    const ENR_KEY_IP_6: &'static str = "ip6";
    const ENR_KEY_UDP: &'static str = "udp";
    const ENR_KEY_UDP_6: &'static str = "udp6";

    /// Check if node supports a given feature.
    fn supports_feature(&self, feature: Feature) -> bool;
    /// Returns the IPv4 address in the 'nat' field if it is defined.
    fn nat4(&self) -> Option<Ipv4Addr>;
    /// Returns the IPv6 address in the 'nat6' field if it is defined.
    fn nat6(&self) -> Option<Ipv6Addr>;
    /// Provides a socket (based on the UDP port), if the 'nat' and 'udp' fields are specified.
    fn udp4_socket_nat(&self) -> Option<SocketAddrV4>;
    /// Provides a socket (based on the UDP port), if the 'nat6' and 'udp6' fields are specified.
    fn udp6_socket_nat(&self) -> Option<SocketAddrV6>;
    /// Set a protocol feature that this node supports. Returns the previous features.
    fn set_feature(&mut self, enr_key: &K, feature: Feature) -> Result<Option<u8>, EnrError>;
    /// Updates ENR to show this node is behind a NAT by setting the externally reachable IP of the
    /// node in the 'nat'/'nat6' field and removing any value in the 'ip'/'ip6' field. If this node
    /// is behind a symmetric NAT the value in the 'udp'/'udp6' field is removed. If this node is
    /// behind an asymmetric NAT the 'udp'/'udp6' field is set to the port to hole-punch this node
    /// on. Returns the previous value in the 'ip'/'ip6'field and 'udp'/'udp6' field if any (if ENR
    /// was set in belief that it is not behind a NAT or is port-forwarded, the 'ip'/'ip6' and
    /// 'udp'/'udp6' fields would be set).
    fn set_udp_socket_nat(
        &mut self,
        enr_key: &CombinedKey,
        ip: impl std::convert::Into<IpAddr>,
        port: Option<u16>,
    ) -> Result<Option<SocketAddr>, EnrError>;
}

impl EnrNat<CombinedKey> for Enr {
    fn supports_feature(&self, feature: Feature) -> bool {
        if let Some(supported_features) = self.get(Self::ENR_KEY_FEATURES) {
            if let Some(supported_features_num) = supported_features.first() {
                let feature_num = feature as u8;
                supported_features_num & feature_num == feature_num
            } else {
                false
            }
        } else {
            warn!(
                "Enr of peer {} doesn't contain field 'version'",
                self.node_id()
            );
            false
        }
    }

    fn nat4(&self) -> Option<Ipv4Addr> {
        if let Some(ip_bytes) = self.get(Self::ENR_KEY_NAT) {
            return match ip_bytes.len() {
                4 => {
                    let mut ip = [0_u8; 4];
                    ip.copy_from_slice(ip_bytes);
                    Some(Ipv4Addr::from(ip))
                }
                _ => None,
            };
        }
        None
    }

    fn nat6(&self) -> Option<Ipv6Addr> {
        if let Some(ip_bytes) = self.get(Self::ENR_KEY_NAT_6) {
            return match ip_bytes.len() {
                16 => {
                    let mut ip = [0_u8; 16];
                    ip.copy_from_slice(ip_bytes);
                    Some(Ipv6Addr::from(ip))
                }
                _ => None,
            };
        }
        None
    }

    fn udp4_socket_nat(&self) -> Option<SocketAddrV4> {
        if let Some(ip) = self.nat4() {
            if let Some(udp) = self.udp4() {
                return Some(SocketAddrV4::new(ip, udp));
            }
        }
        None
    }

    fn udp6_socket_nat(&self) -> Option<SocketAddrV6> {
        if let Some(ip6) = self.nat6() {
            if let Some(udp6) = self.udp6() {
                return Some(SocketAddrV6::new(ip6, udp6, 0, 0));
            }
        }
        None
    }

    fn set_feature(
        &mut self,
        enr_key: &CombinedKey,
        feature: Feature,
    ) -> Result<Option<u8>, EnrError> {
        let mut previous_features = None;

        if let Some(features) = self.get(Self::ENR_KEY_FEATURES) {
            if let Some(features_num) = features.first() {
                previous_features = Some(*features_num);
            }
        }
        let new_features_num = if let Some(previous_features) = previous_features {
            previous_features | feature as u8
        } else {
            feature as u8
        };
        self.insert(Self::ENR_KEY_FEATURES, &[new_features_num], enr_key)?;
        Ok(previous_features)
    }

    fn set_udp_socket_nat(
        &mut self,
        enr_key: &CombinedKey,
        ip: impl std::convert::Into<IpAddr>,
        port: Option<u16>,
    ) -> Result<Option<SocketAddr>, EnrError> {
        let ip = ip.into();

        trace!(
            "Updating local enr with reachable ipv4 address {}:{:?} for node behind NAT",
            ip,
            port
        );

        match ip {
            IpAddr::V4(ip4) => {
                // Removing 'ip' field to indicate to peers that this node is behind a NAT and
                // can't listen for incoming connections (until a hole is punched).
                let mut remove = vec![Self::ENR_KEY_IP];
                let ip_bytes = ip4.octets();
                let mut insert: Vec<(&str, &[u8])> = vec![(Self::ENR_KEY_NAT, &ip_bytes)];

                let (prev_removed_values, _) = if let Some(port) = port {
                    let port_bytes = port.to_be_bytes();
                    insert.push((Self::ENR_KEY_UDP, &port_bytes));
                    self.remove_insert(remove.into_iter(), insert.into_iter(), enr_key)?
                } else {
                    remove.push(Self::ENR_KEY_UDP);
                    self.remove_insert(remove.into_iter(), insert.into_iter(), enr_key)?
                };

                if prev_removed_values.len() == 2 {
                    if let Some(prev_ip) = &prev_removed_values[0] {
                        if prev_ip.len() == 4 {
                            let mut buf = [0u8; 4];
                            buf.copy_from_slice(prev_ip);
                            let prev_ip = IpAddr::V4(Ipv4Addr::from(buf));
                            if let Some(prev_port) = &prev_removed_values[1] {
                                let mut buf = [0u8; 2];
                                buf.copy_from_slice(prev_port);
                                return Ok(Some(SocketAddr::new(prev_ip, u16::from_be_bytes(buf))));
                            }
                        }
                    }
                }
                Ok(None)
            }
            IpAddr::V6(ip6) => {
                // Removing 'ip6' field to indicate to peers that this node is behind a NAT and
                // can't listen for incoming connections (until a hole is punched).
                let mut remove = vec![Self::ENR_KEY_IP_6];
                let ip_bytes = ip6.octets();
                let mut insert: Vec<(&str, &[u8])> = vec![(Self::ENR_KEY_NAT_6, &ip_bytes)];

                let (prev_removed_values, _) = if let Some(port) = port {
                    let port_bytes = port.to_be_bytes();
                    insert.push((Self::ENR_KEY_UDP_6, &port_bytes));
                    self.remove_insert(remove.into_iter(), insert.into_iter(), enr_key)?
                } else {
                    remove.push(Self::ENR_KEY_UDP_6);
                    self.remove_insert(remove.into_iter(), insert.into_iter(), enr_key)?
                };

                if prev_removed_values.len() == 2 {
                    if let Some(prev_ip6) = &prev_removed_values[0] {
                        if prev_ip6.len() == 16 {
                            let mut buf = [0u8; 16];
                            buf.copy_from_slice(prev_ip6);
                            let prev_ip6 = IpAddr::V6(Ipv6Addr::from(buf));
                            if let Some(prev_port) = &prev_removed_values[1] {
                                let mut buf = [0u8; 2];
                                buf.copy_from_slice(prev_port);
                                return Ok(Some(SocketAddr::new(
                                    prev_ip6,
                                    u16::from_be_bytes(buf),
                                )));
                            }
                        }
                    }
                }
                Ok(None)
            }
        }
    }
}
