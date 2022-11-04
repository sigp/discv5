//! Provides an extension for ENRs to implement extended NAT-based functions.
use crate::Enr;
use enr::{CombinedKey, EnrError};
use tracing::{debug, trace};

/// The kind of feature that can be supported.
pub type Feature = u8;

/// Represents the decimal notation of the bitfield location for the feature.
pub const NAT_FEATURE: Feature = 1;

/// Discv5 Capable Features.
///
/// This is a bitfield that is stored inside ENRs to indicate which features of Discv5 are
/// supported.
/// Currently the only optional feature is NAT support. This consumes the first bit location.
/// We currently store a single u8, which is fine as RLP encoding strips the leading 0s.
#[derive(Clone, Debug)]
pub struct FeatureBitfield {
    bitfield: u8, // Supports up to 256 unique features
}

impl FeatureBitfield {
    pub fn new() -> Self {
        Self { bitfield: 0 }
    }

    /// Sets the bitfield to indicate support for the NAT feature.
    pub fn set_nat(&mut self) {
        self.bitfield |= NAT_FEATURE;
    }

    /// Returns true if the NAT feature is set.
    pub fn nat(&self) -> bool {
        self.bitfield & NAT_FEATURE == NAT_FEATURE
    }

    /// Enables one or many features.
    pub fn set_features(&mut self, features: Feature) {
        self.bitfield |= features;
    }

    /// Returns if the feature is supported.
    pub fn supports_feature(&self, feature: Feature) -> bool {
        self.bitfield & feature == feature
    }

    /// Returns the decimal representation of the features supported.
    pub fn features(&self) -> Feature {
        self.bitfield
    }
}

impl From<&[u8]> for FeatureBitfield {
    fn from(src: &[u8]) -> Self {
        Self {
            bitfield: src.first().unwrap_or(&0).clone(),
        }
    }
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
    /// Specific helper function to determine if the ENR supports the NAT feature.
    fn supports_nat(&self) -> bool;
    /// Specific helper function to set NAT support in the ENR.
    fn set_nat_feature(&mut self, enr_key: &K) -> Result<Option<Feature>, EnrError>;
    /// Returns the IPv4 address in the 'nat' field if it is defined.
    fn nat4(&self) -> Option<Ipv4Addr>;
    /// Returns the IPv6 address in the 'nat6' field if it is defined.
    fn nat6(&self) -> Option<Ipv6Addr>;
    /// Provides a socket (based on the UDP port), if the 'nat' and 'udp' fields are specified.
    fn udp4_socket_nat(&self) -> Option<SocketAddrV4>;
    /// Provides a socket (based on the UDP port), if the 'nat6' and 'udp6' fields are specified.
    fn udp6_socket_nat(&self) -> Option<SocketAddrV6>;
    /// Set a protocol feature that this node supports. Returns the previous features.
    fn set_features(&mut self, enr_key: &K, feature: Feature) -> Result<Option<Feature>, EnrError>;
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
            let bitfield = FeatureBitfield::from(supported_features);
            bitfield.supports_feature(feature)
        } else {
            debug!(
                "ENR of peer {} doesn't contain field 'feature'",
                self.node_id()
            );
            false
        }
    }

    fn supports_nat(&self) -> bool {
        self.supports_feature(NAT_FEATURE)
    }

    fn set_nat_feature(&mut self, enr_key: &CombinedKey) -> Result<Option<Feature>, EnrError> {
        self.set_features(enr_key, NAT_FEATURE)
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

    fn set_features(
        &mut self,
        enr_key: &CombinedKey,
        features: Feature,
    ) -> Result<Option<u8>, EnrError> {
        let bitfield = {
            if let Some(features) = self.get(Self::ENR_KEY_FEATURES) {
                Some(FeatureBitfield::from(features))
            } else {
                None
            }
        };

        let mut new_bitfield = bitfield.clone().unwrap_or_else(|| FeatureBitfield::new());
        new_bitfield.set_features(features);

        self.insert(Self::ENR_KEY_FEATURES, &[new_bitfield.features()], enr_key)?;
        Ok(bitfield.map(|field| field.features()))
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
