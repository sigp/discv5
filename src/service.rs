//! The base UDP layer of the discv5 service.
//!
//! The `Discv5Service` opens a UDP socket and handles the encoding/decoding of raw Discv5
//! messages. These messages are defined in the `Packet` module.

use super::packet::{Packet, MAGIC_LENGTH};
use futures::{prelude::*, task};
use log::debug;
use std::io;
use std::net::SocketAddr;
use tokio_udp::UdpSocket;

pub(crate) const MAX_PACKET_SIZE: usize = 1280;

/// The main service that handles the transport. Specifically the UDP sockets and packet
/// encoding/decoding.
pub struct Discv5Service {
    /// The UDP socket for interacting over UDP.
    socket: UdpSocket,
    /// The buffer to accept inbound datagrams.
    recv_buffer: [u8; MAX_PACKET_SIZE],
    /// List of discv5 packets to send.
    send_queue: Vec<(SocketAddr, Packet)>,
    /// WhoAreYou Magic Value. Used to decode raw WHOAREYOU packets.
    whoareyou_magic: [u8; MAGIC_LENGTH],
}

impl Discv5Service {
    /// Initializes the UDP socket, can fail when binding the socket.
    pub fn new(socket_addr: SocketAddr, whoareyou_magic: [u8; MAGIC_LENGTH]) -> io::Result<Self> {
        // set up the UDP socket
        let socket = UdpSocket::bind(&socket_addr)?;

        Ok(Discv5Service {
            socket,
            recv_buffer: [0; MAX_PACKET_SIZE],
            send_queue: Vec::new(),
            whoareyou_magic,
        })
    }

    /// Add packets to the send queue.
    pub fn send(&mut self, to: SocketAddr, packet: Packet) {
        self.send_queue.push((to, packet));
    }

    /// Drive reading/writing to the UDP socket.
    pub fn poll(&mut self) -> Async<(SocketAddr, Packet)> {
        // send messages
        while !self.send_queue.is_empty() {
            let (dst, packet) = self.send_queue.remove(0);

            match self.socket.poll_send_to(&packet.encode(), &dst) {
                Ok(Async::Ready(bytes_written)) => {
                    debug_assert_eq!(bytes_written, packet.encode().len());
                }
                Ok(Async::NotReady) => {
                    // didn't write add back and break
                    self.send_queue.insert(0, (dst, packet));
                    // notify to try again
                    task::current().notify();
                    break;
                }
                Err(_) => {
                    self.send_queue.clear();
                    break;
                }
            }
        }

        // handle incoming messages
        loop {
            match self.socket.poll_recv_from(&mut self.recv_buffer) {
                Ok(Async::Ready((length, src))) => {
                    match Packet::decode(&self.recv_buffer[..length], &self.whoareyou_magic) {
                        Ok(p) => {
                            return Async::Ready((src, p));
                        }
                        Err(e) => debug!("Could not decode packet: {:?}", e), // could not decode the packet, drop it
                    }
                }
                Ok(Async::NotReady) => {
                    break;
                }
                Err(_) => {
                    break;
                } // wait for reconnection to poll again.
            }
        }
        Async::NotReady
    }
}
