//! Client to query Roughtime servers.
//!
//! This module provides a client to make Roughtime requests to a single time server. For
//! multi-server measurement sequences see [`MeasurementSequence`](crate::sequence::MeasurementSequence).
//!
//! # Quick Start
//!
//! Use the [`query`] function:
//!
//! ```no_run
//! use client;
//!
//! // Query with authentication. The client automatically verifies the server's signature.
//! let pub_key = Some("AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=");
//! let measurement = client::query("roughtime.int08h.com", 2003, pub_key).unwrap();
//! println!("Server time: {}", measurement.midpoint_datetime());
//!
//! // Unauthenticated query, no verification, not recommended.
//! let measurement = client::query("roughtime.int08h.com", 2003, None).unwrap();
//! println!("Server time: {}", measurement.midpoint_datetime());
//! ```
//!
//! # Advanced Usage
//!
//! A customized [Client] can be configured using [ClientBuilder]:
//!
//! ```no_run
//! use client::Client;
//! use std::time::Duration;
//! use std::net::SocketAddr;
//!
//! let server: SocketAddr = "roughtime.int08h.com:2003".parse().unwrap();
//! let client = Client::builder(server)
//!     .timeout(Duration::from_secs(5))
//!     .build();
//!
//! let measurement = client.query().unwrap();
//! ```
//!
//! # Transport Layer
//!
//! The client uses UDP for network transport. Custom transport implementations can be provided
//! through the [`ClientTransport`] trait for testing or specialized network configurations.
//!
//! [`ClientTransport`]: crate::transport::ClientTransport

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use common::crypto::{make_srv_commitment, random_bytes};
use common::encoding::try_decode_key;
use protocol::cursor::ParseCursor;
use protocol::request::Request;
use protocol::response::Response;
use protocol::tags::{Nonce, PublicKey, SrvCommitment};
use protocol::{FromFrame, ToFrame};

use crate::measurement::Measurement;
use crate::transport::{ClientTransport, UdpTransport};
use crate::{ResponseValidator, validation};

/// Get the time from a single Roughtime server, optionally authenticating the response with the
/// server's public key.
///
/// Performs DNS lookup to resolve `hostname` to an IP address. Uses the first IP address found
/// if `hostname` resolves to more than one address.
///
/// The returned [Measurement] holds the remote server's timestamp along the full [Request] and
/// [Response] structs for more advanced use.
///
/// ```no_run,rust
/// // You can get the public key from the `ecosystem.json` file, or
/// // use `None` for an unauthenticated response.
/// let pub_key = Some("AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=");
///
/// // Query the server
/// let measurement = client::query("roughtime.int08h.com", 2003, pub_key).unwrap();
///
/// // The returned time in Unix epoch seconds
/// println!("Server's time, epoch: {}", measurement.midpoint());
/// // Returned time in human format
/// println!("Server's time, UTC: {}", measurement.midpoint_datetime())
/// ```
pub fn query(hostname: &str, port: u16, key: Option<&str>) -> Result<Measurement, ClientError> {
    let client = Client::new(hostname, port, key)?;
    client.query()
}

/// Things that can go wrong when querying a server
#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("timeout waiting for server response")]
    ServerTimeout,

    #[error("bad server response: {0}")]
    BadResponse(#[from] protocol::error::Error),

    #[error("public key decode failed: {0}")]
    BadPublicKey(#[from] data_encoding::DecodeError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("validation of the server's response failed: {0}")]
    ValidationFailed(#[from] validation::ValidationError),

    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("could not find IP address for '{0}'")]
    DnsLookupFailed(String),
}

pub struct ClientBuilder {
    server: SocketAddr,
    hostname: String,
    transport: Option<Box<dyn ClientTransport>>,
    timeout: Option<Duration>,
    public_key: Option<PublicKey>,
    // TODO(stuart) add protocol version, others?...
}

impl ClientBuilder {
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            hostname: "unknown".to_string(),
            transport: None,
            timeout: None,
            public_key: None,
        }
    }

    pub fn hostname(mut self, hostname: &str) -> Self {
        self.hostname = hostname.to_string();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn transport(mut self, transport: Box<dyn ClientTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn public_key(mut self, public_key: PublicKey) -> Self {
        self.public_key = Some(public_key);
        self
    }

    pub fn build(self) -> Client {
        let timeout = self.timeout.unwrap_or(Self::DEFAULT_TIMEOUT);

        let transport = self
            .transport
            .unwrap_or_else(|| Box::new(UdpTransport::new(timeout)));

        let srv_commit = self
            .public_key
            .map(|public_key| make_srv_commitment(&public_key));

        let validator = match self.public_key {
            Some(public_key) => ResponseValidator::new_with_key(public_key),
            None => ResponseValidator::new(),
        };

        Client {
            transport,
            validator,
            srv_commit,
            server: self.server,
            hostname: self.hostname,
            public_key: self.public_key,
        }
    }
}

pub struct Client {
    pub(crate) server: SocketAddr,
    pub(crate) hostname: String,
    pub(crate) transport: Box<dyn ClientTransport>,
    pub(crate) validator: ResponseValidator,
    pub(crate) public_key: Option<PublicKey>,
    pub(crate) srv_commit: Option<SrvCommitment>,
}

/// Make requests to servers and receive responses
impl Client {
    pub fn builder(server: SocketAddr) -> ClientBuilder {
        ClientBuilder::new(server)
    }

    /// Create a client from a hostname and port, with an optional public key. Performs DNS lookup
    /// to resolve `hostname` to an IP address. Uses the first IP address found if `hostname`
    /// resolves to more than one address.
    pub fn new(hostname: &str, port: u16, pub_key: Option<impl AsRef<str>>) -> Result<Self, ClientError> {
        let host_port = format!("{hostname}:{port}");
        let sock_addr = host_port
            .to_socket_addrs()?
            .next()
            .ok_or(ClientError::DnsLookupFailed(host_port))?;

        let mut builder = Self::builder(sock_addr).hostname(hostname);

        if let Some(encoded_key) = pub_key {
            let pub_key = try_decode_key(encoded_key.as_ref())?;
            builder = builder.public_key(pub_key);
        }

        Ok(builder.build())
    }

    /// Get the time from a server, optionally authenticating the response.
    ///
    /// ```no_run,rust
    /// use client::Client;
    ///
    /// // You can get the public key from the `ecosystem.json` file, or
    /// // use `None` for an unauthenticated response.
    /// let pub_key = Some("AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=");
    ///
    /// // Create the client
    /// let client = Client::new("roughtime.int08h.com", 2002, pub_key).unwrap();
    ///
    /// // Query the server
    /// let measurement = client.query().unwrap();
    ///
    /// // Returned time in human format
    /// println!("Server's time, UTC: {}", measurement.midpoint_datetime());
    /// // Time in Unix epoch seconds
    /// println!("Server's time, epoch: {}", measurement.midpoint());
    /// ```
    pub fn query(&self) -> Result<Measurement, ClientError> {
        let request = self.create_request(None);
        let nbytes = self.send_request(&request)?;
        assert_eq!(nbytes, request.frame_size());

        let response = self.recv_response()?;
        let request_bytes = request.as_frame_bytes()?;

        // validate() ensures that the response is valid and authentic
        let _midpoint = self.validator.validate(&request_bytes, &response)?;

        Measurement::builder()
            .server(self.server)
            .hostname(self.hostname.clone())
            .public_key(self.public_key)
            .request(request)
            .response(response)
            .rand_value(None)
            .prior_response(None)
            .build()
    }

    /// Create a new Roughtime [Request] using the provided [Nonce], or generate a random nonce
    /// if none was provided.
    fn create_request(&self, nonce: Option<Nonce>) -> Request {
        let nonce = nonce.unwrap_or_else(|| Nonce::from(random_bytes::<32>()));

        if let Some(srv_commit) = &self.srv_commit {
            Request::new_with_server(&nonce, srv_commit)
        } else {
            Request::new(&nonce)
        }
    }

    fn send_request(&self, request: &Request) -> Result<usize, ClientError> {
        let request_bytes = request.as_frame_bytes()?;
        self.transport.send(&request_bytes, self.server)
    }

    fn recv_response(&self) -> Result<Response, ClientError> {
        let mut buf = [0u8; 1024];
        let (nbytes, _addr) = self.transport.recv(&mut buf)?;
        let mut cursor = ParseCursor::new(&mut buf[..nbytes]);
        let response = Response::from_frame(&mut cursor)?;

        Ok(response)
    }
}
