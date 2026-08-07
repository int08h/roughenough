//! Abstraction for network transport mechanisms used by clients.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use tracing::{debug, trace};

use crate::ClientError;

/// Abstraction for network transport mechanisms used by clients.
/// Allows clients to work with different protocols (UDP, TCP, etc.) through a common interface.
pub trait ClientTransport {
    /// Sends data to the specified network address.
    /// Returns the number of bytes sent or an error if the operation fails.
    fn send(&self, data: &[u8], addr: SocketAddr) -> Result<usize, ClientError>;

    /// Receives data from any network address.
    /// Returns the number of bytes received and the sender's address, or an error on failure.
    fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError>;
}

/// UDP implementation of ClientTransport.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn new(addr: &SocketAddr, timeout: Duration) -> Self {
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).unwrap();
        socket.set_read_timeout(Some(timeout)).unwrap();
        socket.set_write_timeout(Some(timeout)).unwrap();

        Self { socket }
    }
}

impl ClientTransport for UdpTransport {
    fn send(&self, data: &[u8], addr: SocketAddr) -> Result<usize, ClientError> {
        debug!("sending {} bytes to {}", data.len(), addr);
        trace_dump(data)?;
        Ok(self.socket.send_to(data, addr)?)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError> {
        match self.socket.recv_from(buf) {
            Ok((nbytes, addr)) => {
                debug!("received {} bytes from {}", nbytes, addr);
                trace_dump(&buf[..nbytes])?;
                Ok((nbytes, addr))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    Err(ClientError::ServerTimeout)
                } else {
                    Err(ClientError::IoError(e))
                }
            }
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
        let transport = UdpTransport::new(&silent_addr, timeout);

        let sent = transport.send(b"anyone there?", silent_addr).unwrap();
        assert_eq!(sent, 13);

        let start = Instant::now();
        let mut buf = [0u8; 64];
        match transport.recv(&mut buf) {
            Err(ClientError::ServerTimeout) => {}
            other => panic!("expected ServerTimeout, got {other:?}"),
        }

        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn send_and_recv_round_trip() {
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();

        let transport = UdpTransport::new(&echo_addr, Duration::from_secs(2));
        transport.send(b"ping", echo_addr).unwrap();

        // Echo the datagram back to the transport's ephemeral port
        let mut echo_buf = [0u8; 16];
        let (n, from) = echo.recv_from(&mut echo_buf).unwrap();
        echo.send_to(&echo_buf[..n], from).unwrap();

        let mut buf = [0u8; 16];
        let (n, _addr) = transport.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
    }
}
