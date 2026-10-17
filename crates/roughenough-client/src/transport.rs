//! Abstraction for network transport mechanisms used by clients.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tracing::{debug, trace};

use crate::ClientError;

/// Abstraction for network transport mechanisms used by clients.
/// Allows clients to work with different protocols (UDP, TCP, etc.) through a common interface.
/// A transport talks to exactly one server, fixed when it is created.
pub trait ClientTransport {
    /// Sends `data` to the server.
    fn send(&self, data: &[u8]) -> Result<(), ClientError>;

    /// Receives one message from the server into `buf`, returning its length.
    fn recv(&self, buf: &mut [u8]) -> Result<usize, ClientError>;
}

/// UDP implementation of ClientTransport.
pub struct UdpTransport {
    socket: UdpSocket,
    server: SocketAddr,
}

impl UdpTransport {
    /// Creates a UDP socket connected to `server`. Connecting makes the kernel drop datagrams
    /// from any other source, and surfaces ICMP port unreachable as an error on `recv` rather
    /// than a timeout.
    pub fn new(server: SocketAddr, timeout: Duration) -> std::io::Result<Self> {
        let bind_addr = match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(server)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        Ok(Self { socket, server })
    }
}

impl ClientTransport for UdpTransport {
    fn send(&self, data: &[u8]) -> Result<(), ClientError> {
        debug!("sending {} bytes to {}", data.len(), self.server);
        trace_dump(data)?;
        self.socket.send(data)?;
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, ClientError> {
        match self.socket.recv(buf) {
            Ok(nbytes) => {
                debug!("received {} bytes from {}", nbytes, self.server);
                trace_dump(&buf[..nbytes])?;
                Ok(nbytes)
            }
            // Windows reports an expired read timeout as TimedOut rather than WouldBlock
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Err(ClientError::ServerTimeout)
            }
            Err(e) => Err(ClientError::IoError(e)),
        }
    }
}

fn trace_dump(data: &[u8]) -> Result<(), ClientError> {
    if tracing::enabled!(tracing::Level::TRACE) {
        let mut dump = Vec::new();
        roughenough_common::encoding::hexdump(data, &mut dump)?;
        trace!("\n{}", String::from_utf8_lossy(&dump));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn recv_from_silent_server_is_server_timeout() {
        // A bound socket that never answers
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let silent_addr = silent.local_addr().unwrap();

        let timeout = Duration::from_millis(100);
        let transport = UdpTransport::new(silent_addr, timeout).unwrap();

        transport.send(b"anyone there?").unwrap();

        let start = Instant::now();
        let mut buf = [0u8; 64];
        match transport.recv(&mut buf) {
            Err(ClientError::ServerTimeout) => {}
            other => panic!("expected ServerTimeout, got {other:?}"),
        }

        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn datagrams_from_other_sources_are_dropped() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let transport = UdpTransport::new(silent_addr, Duration::from_millis(100)).unwrap();
        transport.send(b"hello").unwrap();

        let intruder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = transport.socket.local_addr().unwrap();
        intruder.send_to(b"injected", local).unwrap();

        let mut buf = [0u8; 64];
        match transport.recv(&mut buf) {
            Err(ClientError::ServerTimeout) => {}
            other => panic!("expected ServerTimeout, got {other:?}"),
        }
    }

    #[test]
    fn send_and_recv_round_trip() {
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();

        let transport = UdpTransport::new(echo_addr, Duration::from_secs(2)).unwrap();
        transport.send(b"ping").unwrap();

        // Echo the datagram back to the transport's ephemeral port
        let mut echo_buf = [0u8; 16];
        let (n, from) = echo.recv_from(&mut echo_buf).unwrap();
        echo.send_to(&echo_buf[..n], from).unwrap();

        let mut buf = [0u8; 16];
        let n = transport.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::SocketAddr;

    use roughenough_common::clocksource::ClockSource;
    use roughenough_protocol::request::Request;
    use roughenough_protocol::tags::ProtocolVersion;
    use roughenough_protocol::{FromFrame, ToFrame};
    use roughenough_server::test_utils::TestContext;

    use super::ClientTransport;
    use crate::{Client, ClientError};

    pub(crate) fn test_addr() -> SocketAddr {
        "127.0.0.1:2003".parse().unwrap()
    }

    pub(crate) struct InProcessTransport {
        ctx: RefCell<TestContext>,
        last_request: RefCell<Vec<u8>>,
        pre_queue: RefCell<VecDeque<Vec<u8>>>,
        starve: bool,
    }

    impl InProcessTransport {
        pub(crate) fn new(ctx: TestContext) -> Self {
            Self {
                ctx: RefCell::new(ctx),
                last_request: RefCell::new(Vec::new()),
                pre_queue: RefCell::new(VecDeque::new()),
                starve: false,
            }
        }
    }

    impl ClientTransport for InProcessTransport {
        fn send(&self, data: &[u8]) -> Result<(), ClientError> {
            *self.last_request.borrow_mut() = data.to_vec();
            Ok(())
        }

        fn recv(&self, buf: &mut [u8]) -> Result<usize, ClientError> {
            if let Some(canned) = self.pre_queue.borrow_mut().pop_front() {
                buf[..canned.len()].copy_from_slice(&canned);
                return Ok(canned.len());
            }

            if self.starve {
                return Err(ClientError::ServerTimeout);
            }

            let frame = self.last_request.borrow().clone();
            let request = Request::from_frame_bytes(&frame).expect("mock got a valid request");

            let mut ctx = self.ctx.borrow_mut();
            ctx.response_handler.clear();
            let version = ProtocolVersion::negotiate(request.ver().versions())
                .expect("mock got a request offering version 1");
            ctx.response_handler
                .add_request(&frame, request, version, test_addr());

            let mut out = Vec::new();
            ctx.response_handler
                .process_responses(|_addr, bytes| out.extend_from_slice(bytes));

            buf[..out.len()].copy_from_slice(&out);
            Ok(out.len())
        }
    }

    /// A client answered by an in-process server, with `stale_count` valid
    /// responses for an unrelated nonce delivered ahead of the real answer
    pub(crate) fn client_with_stale_datagrams(stale_count: usize, starve: bool) -> Client {
        let mut ctx = TestContext::new(64);
        let now = ClockSource::System.epoch_seconds();

        // A signed response for a different request: signatures verify but
        // the Merkle proof cannot match the round's nonce
        let (_req, stale) = ctx.create_interaction_pair(now);
        let stale_bytes = stale.as_frame_bytes().unwrap();

        let pub_key = ctx.key_source.public_key();
        let mut transport = InProcessTransport::new(ctx);
        for _ in 0..stale_count {
            transport.pre_queue.get_mut().push_back(stale_bytes.clone());
        }
        transport.starve = starve;

        Client::builder(test_addr())
            .public_key(pub_key)
            .transport(Box::new(transport))
            .build()
            .unwrap()
    }
}
