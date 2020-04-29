//! The base UDP layer of the discv5 service.
//!
//! The `Discv5Service` opens a UDP socket and handles the encoding/decoding of raw Discv5
//! messages. These messages are defined in the `Packet` module.

use super::packet::{Packet, MAGIC_LENGTH};
use futures::prelude::*;
use log::debug;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::net::UdpSocket;

pub(crate) const MAX_PACKET_SIZE: usize = 1280;

/// The main service that handles the transport. Specifically the UDP sockets and packet
/// encoding/decoding.
pub struct Discv5Service {
    /// The UDP socket for interacting over UDP.
    socket: UdpSocket,
    /// List of discv5 packets to send.
    send_queue: Vec<(SocketAddr, Packet)>,
    /// The buffer to accept inbound datagrams.
    recv_buffer: [u8; MAX_PACKET_SIZE],
    /// WhoAreYou Magic Value. Used to decode raw WHOAREYOU packets.
    whoareyou_magic: [u8; MAGIC_LENGTH],
    /// Waker to awake the thread on new messages.
    waker: Option<Waker>,
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
        let socket = UdpSocket::from_std(socket)?;

        Ok(Discv5Service {
            socket,
            send_queue: Vec::new(),
            recv_buffer: [0; MAX_PACKET_SIZE],
            whoareyou_magic,
            waker: None,
        })
    }

    /// Add packets to the send queue.
    pub fn send(&mut self, to: SocketAddr, packet: Packet) {
        self.send_queue.push((to, packet));
        if let Some(waker) = &self.waker {
            waker.wake_by_ref()
        }
    }
}

impl Stream for Discv5Service {
    type Item = (SocketAddr, Packet);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();
        if let Some(waker) = &s.waker {
            if waker.will_wake(cx.waker()) {
                s.waker = Some(cx.waker().clone());
            }
        } else {
            s.waker = Some(cx.waker().clone());
        }

        // send messages
        while !s.send_queue.is_empty() {
            let (dst, packet) = s.send_queue.remove(0);

            match s.socket.poll_send_to(cx, &packet.encode(), &dst) {
                Poll::Ready(Ok(bytes_written)) => {
                    debug_assert_eq!(bytes_written, packet.encode().len());
                }
                Poll::Pending => {
                    // didn't write add back and break
                    s.send_queue.insert(0, (dst, packet));
                    // notify to try again
                    cx.waker().wake_by_ref();
                    break;
                }
                Poll::Ready(Err(_)) => {
                    s.send_queue.clear();
                    break;
                }
            }
        }

        // handle incoming messages
        loop {
            match s.socket.poll_recv_from(cx, &mut s.recv_buffer) {
                Poll::Ready(Ok((length, src))) => {
                    let whoareyou_magic = s.whoareyou_magic;
                    match Packet::decode(&s.recv_buffer[..length], &whoareyou_magic) {
                        Ok(p) => {
                            return Poll::Ready(Some((src, p)));
                        }
                        Err(e) => debug!("Could not decode packet: {:?}", e), // could not decode the packet, drop it
                    }
                }
                Poll::Pending => {
                    break;
                }
                Poll::Ready(Err(_)) => {
                    break;
                } // wait for reconnection to poll again.
            }
        }
        Poll::Pending
    }
}
