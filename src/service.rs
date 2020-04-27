//! The base UDP layer of the discv5 service.
//!
//! The `Discv5Service` opens a UDP socket and handles the encoding/decoding of raw Discv5
//! messages. These messages are defined in the `Packet` module.

use super::packet::{Packet, MAGIC_LENGTH};
use async_std::net::UdpSocket;
use futures::prelude::*;
use log::debug;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

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
        let socket = {
            #[cfg(unix)]
            fn platform_specific(s: &net2::UdpBuilder) -> io::Result<()> {
                net2::unix::UnixUdpBuilderExt::reuse_port(s, true)?;
                Ok(())
            }
            #[cfg(not(unix))]
            fn platform_specific(_: &net2::UdpBuilder) -> io::Result<()> {
                Ok(())
            }
            let builder = net2::UdpBuilder::new_v4()?;
            builder.reuse_address(true)?;
            platform_specific(&builder)?;
            builder.bind(socket_addr)?
        };
        let socket = UdpSocket::from(socket);

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
    pub async fn poll(&mut self) -> (SocketAddr, Packet) {
        loop {
            // send messages
            while !self.send_queue.is_empty() {
                let (dst, packet) = self.send_queue.remove(0);

                match self.socket.send_to(&packet.encode(), &dst).await {
                    Ok(bytes_written) => {
                        debug_assert_eq!(bytes_written, packet.encode().len());
                    }
                    Err(_) => {
                        self.send_queue.clear();
                        break;
                    }
                }
            }

            // handle incoming messages
            match self.socket.recv_from(&mut self.recv_buffer).await {
                Ok((length, src)) => {
                    match Packet::decode(&self.recv_buffer[..length], &self.whoareyou_magic) {
                        Ok(p) => return (src, p),
                        Err(e) => debug!("Could not decode packet: {:?}", e), // could not decode the packet, drop it
                    }
                }
                Err(_) => {}
            };
        }
    }
}

impl Stream for Discv5Service {
    type Item = (SocketAddr, Packet);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match Box::pin(self.poll()).as_mut().poll(cx) {
            Poll::Ready(v) => Poll::Ready(Some(v)),
            Poll::Pending => Poll::Pending,
        }
    }
}
