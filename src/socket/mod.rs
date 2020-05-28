
use tokio::mpsc;


/// Convenience objects for setting up the recv handler.
pub struct SocketConfig<T: Executor> {
    pub socket_addr: SocketAddr,
    pub filter_config: FilterConfig,
    pub executor: T
    pub whoareyou_magic: [u8; MAGIC_LENGTH],
}

/// Creates the UDP socket and handles the exit futures for the send/recv UDP handlers. 
pub struct Socket {
    sender_exit: tokio::oneshot::Sender,
    recv_exit: tokio::oneshot::Sender,
}

impl Socket {
    /// Creates a UDP socket, spawns a send/recv task and returns the channels. 
    /// If this struct is dropped, the send/recv tasks will shutdown.
    pub(crate) fn new(config: SocketConfig) -> (mpsc::Receiver<InboundPacket>, mpsc::Sender<OutboundPacket>, Self) {

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
            builder.bind(config.socket_addr)?
        };
        let socket = UdpSocket::from_std(socket)?;

        // create the channel to receive decoded packets from the recv handler
        let (handler_send, handler_recv) = tokio::mpsc::channel(30);

        // split the UDP socket
        let (recv_udp, send_udp) = socket.split();

        // spawn the recv handler
        let recv_exit = RecvHandler::spawn(&config, handler_send, recv_udp);
        // spawn the sender handler
        let (sender, sender_exit) = SendHandler::spawn(&config, send_udp);

        let sock = Socket { sender_ext, recv_exit };
        return (handler_recv, sender, sock);
    }
}

impl<T> std::ops::Drop for Socket<T> {
    // close the send/recv handlers
    fn drop(&mut self) {
        let _ = self.sender_exit.send(());
        let _ = self.recv_exit.send(());
    }
}
