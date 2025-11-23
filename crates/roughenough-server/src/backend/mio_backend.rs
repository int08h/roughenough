//! Mio-based network I/O backend.
//!
//! This backend uses the mio crate for poll-based asynchronous I/O.
//! Each `recv_from` and `send_to` call is a separate syscall.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token};

use super::{CollectResult, NetworkBackend};
use crate::metrics::network::NetworkMetrics;

const READER: Token = Token(0);
const RECV_BUFFER_SIZE: usize = 1024;

/// Mio-based network backend using poll for event notification.
///
/// This is the default backend that works on all platforms. It uses
/// individual `recv_from` and `send_to` calls, resulting in one syscall
/// per packet.
pub struct MioBackend {
    socket: MioUdpSocket,
    poll: Poll,
    events: Events,
    batch_size: usize,
    metrics: NetworkMetrics,
}

impl MioBackend {
    /// Create a new MioBackend wrapping the given socket.
    ///
    /// The socket is registered with the poll instance for readable events.
    /// `batch_size` controls how many packets to attempt receiving per
    /// `collect_requests` call.
    pub fn new(socket: MioUdpSocket, batch_size: usize) -> io::Result<Self> {
        let poll = Poll::new()?;
        let mut sock = socket;
        poll.registry()
            .register(&mut sock, READER, Interest::READABLE)?;

        Ok(Self {
            socket: sock,
            poll,
            events: Events::with_capacity(1024),
            batch_size,
            metrics: NetworkMetrics::default(),
        })
    }
}

impl NetworkBackend for MioBackend {
    fn collect_requests<F>(&mut self, mut callback: F) -> CollectResult
    where
        F: FnMut(&mut [u8], SocketAddr),
    {
        let mut buf = [0u8; RECV_BUFFER_SIZE];

        for _ in 0..self.batch_size {
            self.metrics.num_recv_syscalls += 1;

            match self.socket.recv_from(&mut buf) {
                Ok((nbytes, src_addr)) => {
                    callback(&mut buf[..nbytes], src_addr);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.metrics.num_recv_wouldblock += 1;
                    return CollectResult::Empty;
                }
                Err(_) => {
                    self.metrics.num_failed_recvs += 1;
                    return CollectResult::MoreData;
                }
            }
        }
        CollectResult::MoreData
    }

    fn send_response(&mut self, data: &[u8], addr: SocketAddr) {
        self.metrics.num_send_syscalls += 1;

        match self.socket.send_to(data, addr) {
            Ok(_) => {
                self.metrics.num_successful_sends += 1;
            }
            Err(_) => {
                self.metrics.num_failed_sends += 1;
            }
        }
    }

    fn flush(&mut self) {
        // No-op: MioBackend sends immediately
    }

    fn wait_for_events(&mut self, timeout: Duration) -> bool {
        match self.poll.poll(&mut self.events, Some(timeout)) {
            Ok(_) => !self.events.is_empty(),
            Err(_) => {
                self.metrics.num_failed_polls += 1;
                false
            }
        }
    }

    fn metrics(&self) -> NetworkMetrics {
        self.metrics
    }

    fn reset_metrics(&mut self) {
        self.metrics = NetworkMetrics::default();
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;

    #[test]
    fn test_mio_backend_creation() {
        let std_socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
        std_socket.set_nonblocking(true).expect("set nonblocking");
        let mio_socket = MioUdpSocket::from_std(std_socket);

        let backend = MioBackend::new(mio_socket, 64);
        assert!(backend.is_ok());

        let backend = backend.unwrap();
        assert_eq!(backend.batch_size, 64);
        assert_eq!(backend.metrics.num_recv_syscalls, 0);
    }

    #[test]
    fn test_mio_backend_empty_socket() {
        let std_socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
        std_socket.set_nonblocking(true).expect("set nonblocking");
        let mio_socket = MioUdpSocket::from_std(std_socket);

        let mut backend = MioBackend::new(mio_socket, 64).expect("create backend");

        let result = backend.collect_requests(|_data, _addr| {
            panic!("should not receive any data");
        });

        assert_eq!(result, CollectResult::Empty);
        assert_eq!(backend.metrics.num_recv_wouldblock, 1);
        assert_eq!(backend.metrics.num_recv_syscalls, 1);
    }
}
