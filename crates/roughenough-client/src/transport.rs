//! Abstraction for network transport mechanisms used by clients.

use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tracing::{debug, trace};

use crate::ClientError;

/// Abstraction for network transport mechanisms used by clients.
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
    /// Creates a UDP socket connected to `server`.
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
        hexdump(data, &mut dump)?;
        trace!("\n{}", String::from_utf8_lossy(&dump));
    }
    Ok(())
}

/// Write a hex dump of the provided data to the writer.
///
/// The output format is similar to traditional hex dump tools:
/// - 8-digit hex offset
/// - 16 bytes per line in hex (grouped by 2 bytes)
/// - ASCII representation on the right
fn hexdump<W: Write>(data: &[u8], writer: &mut W) -> std::io::Result<()> {
    const BYTES_PER_LINE: usize = 16;

    for (offset, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        write!(writer, "{:08x}: ", offset * BYTES_PER_LINE)?;

        for (i, byte) in chunk.iter().enumerate() {
            write!(writer, "{byte:02x}")?;
            if i % 2 == 1 {
                write!(writer, " ")?;
            }
        }

        let padding = BYTES_PER_LINE - chunk.len();
        for i in 0..padding {
            write!(writer, "  ")?;
            if (chunk.len() + i) % 2 == 1 {
                write!(writer, " ")?;
            }
        }

        write!(writer, " |")?;
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            write!(writer, "{ch}")?;
        }
        writeln!(writer, "|")?;
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

    #[test]
    fn test_hexdump() {
        let data = b"Hello, World! This is a test.";
        let mut output = Vec::new();

        hexdump(data, &mut output).unwrap();
        let result = String::from_utf8(output).unwrap();

        assert!(result.contains("00000000:"));
        assert!(result.contains("4865 6c6c")); // "Hell" with space
        assert!(result.contains("|Hello, World! Th|"));
        assert!(result.contains("|is is a test.|"));
    }

    #[test]
    fn test_hexdump_short() {
        let data = b"Test";
        let mut output = Vec::new();

        hexdump(data, &mut output).unwrap();
        let result = String::from_utf8(output).unwrap();

        assert!(result.contains("00000000: 5465 7374"));
        assert!(result.contains("|Test|"));
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::SocketAddr;

    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use roughenough_common::clocksource::ClockSource;
    use roughenough_merkle::MerkleTree;
    use roughenough_protocol::request::Request;
    use roughenough_protocol::tags::{
        Delegation, MerkleRoot, ProtocolVersion, PublicKey, SignedResponse, SupportedVersions,
    };
    use roughenough_protocol::util::test_utils::{build_msg, insert_tag};
    use roughenough_protocol::{FromFrame, ToFrame, ToWire};
    use roughenough_server::test_utils::TestContext;

    use super::ClientTransport;
    use crate::{Client, ClientError};

    pub(crate) fn test_addr() -> SocketAddr {
        "127.0.0.1:2003".parse().unwrap()
    }

    // Fixed seeds keep the long-term key stable across calls, so a client can be built with it
    // before any response exists.
    fn long_term_key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[0x11; 32]).unwrap()
    }

    fn online_key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[0x22; 32]).unwrap()
    }

    /// The long-term public key that signs every [`signed_response`]
    pub(crate) fn signed_response_key() -> PublicKey {
        let longterm = long_term_key();
        PublicKey::try_from(longterm.public_key().as_ref()).unwrap()
    }

    /// A framed response to `request_bytes` carrying `ver` and `vers`, built by hand rather than
    /// by a server so it can say things our server never would. With `greased`, undefined tags
    /// are spliced into DELE, SREP, and the top-level message, and signatures cover the bytes as
    /// sent. Returns the long-term public key and the framed response.
    pub(crate) fn signed_response(
        request_bytes: &[u8],
        ver: ProtocolVersion,
        vers: &[ProtocolVersion],
        greased: bool,
    ) -> (PublicKey, Vec<u8>) {
        let longterm = long_term_key();
        let online = online_key();
        let request = Request::from_frame_bytes(request_bytes).unwrap();
        let grease = |bytes: Vec<u8>, value: &[u8]| {
            if greased {
                insert_tag(&bytes, *b"GREZ", value)
            } else {
                bytes
            }
        };

        // Single-request batch: ROOT is the leaf hash of the request packet
        let mut tree = MerkleTree::new();
        tree.push_leaf(request_bytes);
        let root = tree.compute_root();

        let mut dele = Delegation::default();
        dele.set_pubk(PublicKey::try_from(online.public_key().as_ref()).unwrap());
        dele.set_mint(0);
        dele.set_maxt(u64::MAX);
        let dele_bytes = grease(dele.as_bytes().unwrap(), &[0xcc; 4]);

        let mut to_sign = ver.dele_prefix().to_vec();
        to_sign.extend_from_slice(&dele_bytes);
        let dele_sig = longterm.sign(&to_sign);

        let cert_bytes = build_msg(&[
            (*b"SIG\x00", dele_sig.as_ref().to_vec()),
            (*b"DELE", dele_bytes),
        ]);

        let mut srep = SignedResponse::default();
        srep.set_ver(ver);
        srep.set_radi(5);
        srep.set_midp(1000);
        srep.set_vers(&SupportedVersions::new(vers));
        srep.set_root(&MerkleRoot::from(root));
        let srep_bytes = grease(srep.as_bytes().unwrap(), &[0xdd; 8]);

        let mut to_sign = ver.srep_prefix().to_vec();
        to_sign.extend_from_slice(&srep_bytes);
        let srep_sig = online.sign(&to_sign);

        let mut fields = vec![
            (*b"SIG\x00", srep_sig.as_ref().to_vec()),
            (*b"NONC", request.nonc().as_ref().to_vec()),
            (*b"TYPE", 1u32.to_le_bytes().to_vec()),
            (*b"PATH", vec![]),
            (*b"SREP", srep_bytes),
            (*b"CERT", cert_bytes),
            (*b"INDX", 0u32.to_le_bytes().to_vec()),
        ];
        if greased {
            fields.push((*b"GREZ", vec![0xee; 4]));
        }
        let msg = build_msg(&fields);

        let mut response_bytes = Vec::new();
        response_bytes.extend_from_slice(b"ROUGHTIM");
        response_bytes.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        response_bytes.extend_from_slice(&msg);

        (signed_response_key(), response_bytes)
    }

    /// Answers each request with a [`signed_response`] carrying the `ver` and `vers` given at
    /// construction. Build the client with [`signed_response_key`].
    pub(crate) struct ResponderTransport {
        ver: ProtocolVersion,
        vers: Vec<ProtocolVersion>,
        last_request: RefCell<Vec<u8>>,
    }

    impl ResponderTransport {
        pub(crate) fn new(ver: ProtocolVersion, vers: &[ProtocolVersion]) -> Self {
            Self {
                ver,
                vers: vers.to_vec(),
                last_request: RefCell::new(Vec::new()),
            }
        }
    }

    impl ClientTransport for ResponderTransport {
        fn send(&self, data: &[u8]) -> Result<(), ClientError> {
            *self.last_request.borrow_mut() = data.to_vec();
            Ok(())
        }

        fn recv(&self, buf: &mut [u8]) -> Result<usize, ClientError> {
            let (_, response) =
                signed_response(&self.last_request.borrow(), self.ver, &self.vers, false);
            buf[..response.len()].copy_from_slice(&response);
            Ok(response.len())
        }
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
