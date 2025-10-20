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
    pub fn new(timeout: Duration) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
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
