use crate::Enr;
use std::net::SocketAddr;
///! A set of configuration parameters to tune the discovery protocol.

// TODO: move to another file
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpMode {
    Ip4,
    Ip6 { enable_mapped_addresses: bool },
}

impl Default for IpMode {
    fn default() -> Self {
        IpMode::Ip4
    }
}

impl IpMode {
    pub fn is_ipv4(&self) -> bool {
        self == &IpMode::Ip4
    }

    /// Get the contactable Socket address of an Enr under current configuration.
    pub fn get_contactable_addr(&self, enr: &Enr) -> Option<SocketAddr> {
        match self {
            IpMode::Ip4 => enr.udp4_socket().map(SocketAddr::V4),
            IpMode::Ip6 {
                enable_mapped_addresses,
            } => {
                if *enable_mapped_addresses {
                    // NOTE: general consensus is that ipv6 addresses should be preferred.
                    // NOTE: There is nothing in the spec preventing compat/mapped addresses from being
                    // transmited in the ENR. Here we choose to enforce canonical addresses since
                    // it simplies the logic of matching socket_addr verification.
                    enr.udp6_socket()
                        .and_then(|socket_addr| {
                            if to_ipv4_mapped(socket_addr.ip()).is_some() {
                                None
                            } else {
                                Some(SocketAddr::V6(socket_addr))
                            }
                        })
                        .or_else(|| enr.udp4_socket().map(SocketAddr::V4))
                } else {
                    enr.udp6_socket().map(SocketAddr::V6)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    const IP6_TEST_PORT: u16 = 9000;
    const IP4_TEST_PORT: u16 = 9090;

    /// Structure to make each case clear
    struct TestCase {
        name: &'static str,
        enr_ip4: Option<Ipv4Addr>,
        enr_ip6: Option<Ipv6Addr>,
        ip_mode: IpMode,
        expected_socket_addr: Option<SocketAddr>,
    }

    impl TestCase {
        fn new(name: &'static str) -> TestCase {
            TestCase {
                name,
                enr_ip4: None,
                enr_ip6: None,
                ip_mode: IpMode::Ip4,
                expected_socket_addr: None,
            }
        }

        fn enr_ip4(&mut self, ip4: Ipv4Addr) -> &mut Self {
            self.enr_ip4 = Some(ip4);
            self
        }

        fn enr_ip6(&mut self, ip6: Ipv6Addr) -> &mut Self {
            self.enr_ip6 = Some(ip6);
            self
        }

        fn ip_mode(&mut self, mode: IpMode) -> &mut Self {
            self.ip_mode = mode;
            self
        }

        fn expect_ip4(&mut self, ip4: Ipv4Addr) -> &mut Self {
            self.expected_socket_addr = Some(SocketAddr::V4(SocketAddrV4::new(ip4, IP4_TEST_PORT)));
            self
        }

        fn expect_ip6(&mut self, ip6: Ipv6Addr) -> &mut Self {
            self.expected_socket_addr =
                Some(SocketAddr::V6(SocketAddrV6::new(ip6, IP6_TEST_PORT, 0, 0)));
            self
        }

        fn test(&self) {
            let test_enr = {
                let builder = &mut enr::EnrBuilder::new("v4");
                if let Some(ip4) = self.enr_ip4 {
                    builder.ip4(ip4).udp4(IP4_TEST_PORT);
                }
                if let Some(ip6) = self.enr_ip6 {
                    builder.ip6(ip6).udp6(IP6_TEST_PORT);
                }
                builder
                    .build(&enr::CombinedKey::generate_secp256k1())
                    .unwrap()
            };

            assert_eq!(
                self.ip_mode.get_contactable_addr(&test_enr),
                self.expected_socket_addr,
                "Wrong contactable address for test '{}' with ip mode {:?}",
                self.name,
                self.ip_mode
            )
        }
    }

    #[test]
    fn empty_enr_no_contactable_address() {
        // Empty ENR
        TestCase::new("Empty enr is non contactable by ip4 node")
            .ip_mode(IpMode::Ip4)
            .test();

        TestCase::new("Empty enr is not contactable by ip6 only node")
            .ip_mode(IpMode::Ip6 {
                enable_mapped_addresses: false,
            })
            .test();

        TestCase::new("Empty enr is not contactable by dual stack node")
            .ip_mode(IpMode::Ip6 {
                enable_mapped_addresses: true,
            })
            .test();
    }

    #[test]
    fn ipv4_only_enr_contactable_addresses() {
        // Ip4 only ENR
        TestCase::new("Ipv4 only enr is contactable by ip4 node")
            .enr_ip4(Ipv4Addr::LOCALHOST)
            .ip_mode(IpMode::Ip4)
            .expect_ip4(Ipv4Addr::LOCALHOST)
            .test();

        TestCase::new("Ipv4 only enr is not contactable by ip6 only node")
            .enr_ip4(Ipv4Addr::LOCALHOST)
            .ip_mode(IpMode::Ip6 {
                enable_mapped_addresses: false,
            })
            .test();

        TestCase::new("Ipv4 only enr is contactable by dual stack node")
            .enr_ip4(Ipv4Addr::LOCALHOST)
            .ip_mode(IpMode::Ip6 {
                enable_mapped_addresses: true,
            })
            .expect_ip4(Ipv4Addr::LOCALHOST)
            .test();
    }

    #[test]
    fn ipv6_only_enr_contactable_addresses() {
        // Ip4 only ENR
        TestCase::new("Ipv6 only enr is not contactable by ip4 node")
            .enr_ip6(Ipv6Addr::LOCALHOST)
            .ip_mode(IpMode::Ip4)
            .test();

        TestCase::new("Ipv6 only enr is contactable by ip6 only node")
            .enr_ip6(Ipv6Addr::LOCALHOST)
            .ip_mode(IpMode::Ip6 {
                enable_mapped_addresses: false,
            })
            .expect_ip6(Ipv6Addr::LOCALHOST)
            .test();

        TestCase::new("Ipv6 only enr is contactable by dual stack node")
            .enr_ip6(Ipv6Addr::LOCALHOST)
            .ip_mode(IpMode::Ip6 {
                enable_mapped_addresses: true,
            })
            .expect_ip6(Ipv6Addr::LOCALHOST)
            .test();
    }

    #[test]
    fn dual_stack_enr_contactable_addresses() {
        // Ip4 only ENR
        TestCase::new("Dual stack enr is contactable by ip4 node")
            .enr_ip6(Ipv6Addr::LOCALHOST)
            .enr_ip4(Ipv4Addr::LOCALHOST)
            .ip_mode(IpMode::Ip4)
            .expect_ip4(Ipv4Addr::LOCALHOST)
            .test();

        TestCase::new("Dual stack enr is contactable by ip6 only node")
            .enr_ip6(Ipv6Addr::LOCALHOST)
            .enr_ip4(Ipv4Addr::LOCALHOST)
            .ip_mode(IpMode::Ip6 {
                enable_mapped_addresses: false,
            })
            .expect_ip6(Ipv6Addr::LOCALHOST)
            .test();

        TestCase::new("Dual stack enr is contactable by dual stack node")
            .enr_ip6(Ipv6Addr::LOCALHOST)
            .enr_ip4(Ipv4Addr::LOCALHOST)
            .ip_mode(IpMode::Ip6 {
                enable_mapped_addresses: true,
            })
            .expect_ip6(Ipv6Addr::LOCALHOST)
            .test();
    }
}

/// Copied from https://github.com/rust-lang/rust/issues/27709
/// The current code is behind the `ip` feature.
pub const fn to_ipv4_mapped(ip: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    match ip.octets() {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
            Some(std::net::Ipv4Addr::new(a, b, c, d))
        }
        _ => None,
    }
}
