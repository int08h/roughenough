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
//! use roughenough_client::query;
//!
//! // Query with authentication. The client verifies the server's signature.
//! let pub_key = Some("AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=");
//! let measurement = query("roughtime.int08h.com", 2003, pub_key).unwrap();
//! if let Some(utc) = measurement.midpoint_datetime() {
//!     println!("Server time: {utc}");
//! }
//!
//! // Unauthenticated query, not recommended.
//! let measurement = query("roughtime.int08h.com", 2003, None).unwrap();
//! if let Some(utc) = measurement.midpoint_datetime() {
//!     println!("Server time: {utc}");
//! }
//! ```
//!
//! # Advanced Usage
//!
//! A customized [Client] can be configured using [ClientBuilder]:
//!
//! ```no_run
//! use roughenough_client::Client;
//! use std::time::Duration;
//! use std::net::SocketAddr;
//!
//! let server: SocketAddr = "roughtime.int08h.com:2003".parse().unwrap();
//! let client = Client::builder(server)
//!     .timeout(Duration::from_secs(5))
//!     .build()
//!     .unwrap();
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

use data_encoding::{DecodeError, DecodeKind};
use roughenough_common::crypto::{make_srv_commitment, random_bytes};
use roughenough_common::encoding::try_decode;
use roughenough_protocol::ToFrame;
use roughenough_protocol::request::{MAX_RESPONSE_SIZE, Request};
use roughenough_protocol::tags::{Nonce, ProtocolVersion, PublicKey, SrvCommitment};

use crate::measurement::Measurement;
use crate::transport::{ClientTransport, UdpTransport};
use crate::validation::{ValidationError, check_vers_contains_ver};
use crate::{ResponseValidator, validation};

const MAX_DISCARDED_DATAGRAMS: usize = 8;

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
/// let measurement = roughenough_client::query("roughtime.int08h.com", 2003, pub_key).unwrap();
///
/// // The returned time in Unix epoch seconds
/// println!("Server's time, epoch: {}", measurement.midpoint());
/// // Returned time in human format
/// println!("Server's time, UTC: {:?}", measurement.midpoint_datetime())
/// ```
pub fn query(hostname: &str, port: u16, key: Option<&str>) -> Result<Measurement, ClientError> {
    let client = Client::new(hostname, port, key)?;
    client.query()
}

/// Decode a public key from various encodings (hex, base64, etc).
/// Tries multiple encoding formats until one succeeds.
pub fn try_decode_key(encoded_key: &str) -> Result<PublicKey, DecodeError> {
    let key = try_decode(encoded_key)?;

    PublicKey::try_from(key.as_slice()).map_err(|_| DecodeError {
        position: key.len(),
        kind: DecodeKind::Length,
    })
}

/// Things that can go wrong when querying a server
#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("timeout waiting for server response")]
    ServerTimeout,

    #[error("bad server response: {0}")]
    BadResponse(#[from] roughenough_protocol::error::Error),

    #[error("public key decode failed: {0}")]
    BadPublicKey(#[from] DecodeError),

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
    versions: Option<Vec<ProtocolVersion>>,
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
            versions: None,
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

    /// Protocol versions to offer in requests instead of the default. Must be
    /// non-empty and sorted in ascending wire order (RFC 5.1.1).
    pub fn versions(mut self, versions: &[ProtocolVersion]) -> Self {
        assert!(!versions.is_empty(), "versions must be non-empty");
        self.versions = Some(versions.to_vec());
        self
    }

    /// Fails if no transport was given and the UDP socket cannot be created.
    pub fn build(self) -> Result<Client, ClientError> {
        let timeout = self.timeout.unwrap_or(Self::DEFAULT_TIMEOUT);

        let transport = match self.transport {
            Some(transport) => transport,
            None => Box::new(UdpTransport::new(self.server, timeout)?),
        };

        let srv_commit = self
            .public_key
            .map(|public_key| make_srv_commitment(&public_key));

        let validator = ResponseValidator::new(self.public_key);

        Ok(Client {
            transport,
            validator,
            srv_commit,
            server: self.server,
            hostname: self.hostname,
            public_key: self.public_key,
            versions: self.versions,
        })
    }
}

pub struct Client {
    server: SocketAddr,
    hostname: String,
    transport: Box<dyn ClientTransport>,
    validator: ResponseValidator,
    public_key: Option<PublicKey>,
    srv_commit: Option<SrvCommitment>,
    /// Protocol versions to offer instead of the default, if configured
    versions: Option<Vec<ProtocolVersion>>,
}

/// Make requests to servers and receive responses
impl Client {
    pub fn builder(server: SocketAddr) -> ClientBuilder {
        ClientBuilder::new(server)
    }

    /// Create a client from a hostname and port, with an optional public key. Performs DNS lookup
    /// to resolve `hostname` to an IP address. Uses the first IP address found if `hostname`
    /// resolves to more than one address.
    pub fn new(
        hostname: &str,
        port: u16,
        pub_key: Option<impl AsRef<str>>,
    ) -> Result<Self, ClientError> {
        Self::new_with_versions(hostname, port, pub_key, None)
    }

    /// Like [`Client::new`], additionally configuring the protocol versions to
    /// offer in requests (see [`ClientBuilder::versions`]).
    pub fn new_with_versions(
        hostname: &str,
        port: u16,
        pub_key: Option<impl AsRef<str>>,
        versions: Option<&[ProtocolVersion]>,
    ) -> Result<Self, ClientError> {
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

        if let Some(versions) = versions {
            builder = builder.versions(versions);
        }

        builder.build()
    }

    /// The server's socket address
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// The server's name, used for display and in measurements
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The server's public key, if the client authenticates responses
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    /// Get the time from a server, optionally authenticating the response.
    ///
    /// ```no_run,rust
    /// use roughenough_client::Client;
    ///
    /// // You can get the public key from the `ecosystem.json` file, or
    /// // use `None` for an unauthenticated response.
    /// let pub_key = Some("AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=");
    ///
    /// // Create the client
    /// let client = Client::new("roughtime.int08h.com", 5319, pub_key).unwrap();
    ///
    /// // Query the server
    /// let measurement = client.query().unwrap();
    ///
    /// // Returned time in human format
    /// println!("Server's time, UTC: {:?}", measurement.midpoint_datetime());
    /// // Time in Unix epoch seconds
    /// println!("Server's time, epoch: {}", measurement.midpoint());
    /// ```
    pub fn query(&self) -> Result<Measurement, ClientError> {
        let nonce = Nonce::from(random_bytes::<32>());
        self.exchange(nonce, None)
    }

    /// Send one request using `nonce` and return the validated [Measurement]. `rand_value` is
    /// the chaining value that produced `nonce`, if any, and is recorded in the measurement.
    pub(crate) fn exchange(
        &self,
        nonce: Nonce,
        rand_value: Option<[u8; 32]>,
    ) -> Result<Measurement, ClientError> {
        let request = self.create_request(&nonce);
        let request_bytes = request.as_frame_bytes()?;
        self.transport.send(&request_bytes)?;

        let mut discarded = 0;
        let (response, response_bytes) = loop {
            let mut buf = [0u8; MAX_RESPONSE_SIZE];
            let nbytes = self.transport.recv(&mut buf)?;
            let response_bytes = buf[..nbytes].to_vec();

            let result = self.validator.validate(&request_bytes, &response_bytes);
            match result {
                Ok(response) => break (response, response_bytes),
                // A late or duplicated response to an earlier request fails only the proof
                Err(ValidationError::FailedProof(_)) if discarded < MAX_DISCARDED_DATAGRAMS => {
                    discarded += 1;
                }
                Err(e) => return Err(e.into()),
            }
        };

        check_vers_contains_ver(&response)?;

        Ok(Measurement::new(
            self.server,
            self.hostname.clone(),
            self.public_key,
            request,
            response,
            response_bytes,
            rand_value,
        ))
    }

    fn create_request(&self, nonce: &Nonce) -> Request {
        match (&self.srv_commit, &self.versions) {
            (Some(srv), Some(versions)) => {
                Request::new_with_server_and_versions(nonce, srv, versions)
            }
            (Some(srv), None) => Request::new_with_server(nonce, srv),
            (None, Some(versions)) => Request::new_with_versions(nonce, versions),
            (None, None) => Request::new(nonce),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::testing::{
        ResponderTransport, client_with_stale_datagrams, signed_response_key, test_addr,
    };

    fn test_key() -> PublicKey {
        PublicKey::from([0x42u8; 32])
    }

    #[test]
    fn builder_defaults() {
        let client = Client::builder(test_addr()).build().unwrap();

        assert_eq!(client.server, test_addr());
        assert_eq!(client.hostname, "unknown");
        assert!(client.public_key.is_none());
        assert!(client.srv_commit.is_none());
        assert!(client.versions.is_none());
    }

    #[test]
    fn builder_with_key_derives_srv_commitment() {
        let key = test_key();
        let client = Client::builder(test_addr())
            .public_key(key)
            .build()
            .unwrap();

        assert_eq!(client.public_key, Some(key));
        assert_eq!(client.srv_commit, Some(make_srv_commitment(&key)));
    }

    #[test]
    fn request_without_key_omits_srv() {
        let client = Client::builder(test_addr()).build().unwrap();
        let request = client.create_request(&Nonce::from([0u8; 32]));

        assert!(request.srv().is_none());
    }

    #[test]
    fn request_with_key_carries_srv_commitment() {
        let key = test_key();
        let client = Client::builder(test_addr())
            .public_key(key)
            .build()
            .unwrap();

        let request = client.create_request(&Nonce::from([0u8; 32]));
        assert_eq!(request.srv(), Some(&make_srv_commitment(&key)));
    }

    #[test]
    fn request_carries_configured_versions() {
        let versions = [ProtocolVersion::RFC];
        let client = Client::builder(test_addr())
            .versions(&versions)
            .build()
            .unwrap();

        let request = client.create_request(&Nonce::from([0u8; 32]));
        assert_eq!(request.ver().versions(), &versions[..]);
    }

    #[test]
    fn request_uses_provided_nonce() {
        let client = Client::builder(test_addr()).build().unwrap();
        let nonce = Nonce::from([0x77u8; 32]);

        let request = client.create_request(&nonce);
        assert_eq!(request.nonc(), &nonce);
    }

    #[test]
    fn query_surfaces_transport_timeout() {
        // Transport that never receives anything
        struct DeafTransport;
        impl ClientTransport for DeafTransport {
            fn send(&self, _data: &[u8]) -> Result<(), ClientError> {
                Ok(())
            }
            fn recv(&self, _buf: &mut [u8]) -> Result<usize, ClientError> {
                Err(ClientError::ServerTimeout)
            }
        }

        let client = Client::builder(test_addr())
            .transport(Box::new(DeafTransport))
            .build()
            .unwrap();

        match client.query() {
            Err(ClientError::ServerTimeout) => {}
            other => panic!("expected ServerTimeout, got {other:?}"),
        }
    }

    #[test]
    fn query_skips_stale_datagrams() {
        let client = client_with_stale_datagrams(2, false);

        let result = client.query();
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn query_gives_up_after_too_many_stale_datagrams() {
        let client = client_with_stale_datagrams(MAX_DISCARDED_DATAGRAMS + 1, false);

        match client.query() {
            Err(ClientError::ValidationFailed(ValidationError::FailedProof(_))) => {}
            other => panic!("expected FailedProof, got {other:?}"),
        }
    }

    fn client_answered_with(ver: ProtocolVersion, vers: &[ProtocolVersion]) -> Client {
        Client::builder(test_addr())
            .public_key(signed_response_key())
            .transport(Box::new(ResponderTransport::new(ver, vers)))
            .build()
            .unwrap()
    }

    #[test]
    fn query_rejects_vers_without_ver() {
        let client = client_answered_with(ProtocolVersion::RFC, &[ProtocolVersion::DRAFT]);

        match client.query() {
            Err(ClientError::ValidationFailed(ValidationError::VerNotInVers { .. })) => {}
            other => panic!("expected VerNotInVers, got {other:?}"),
        }

        let client = client_answered_with(ProtocolVersion::RFC, &[ProtocolVersion::RFC]);
        let result = client.query();
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn test_decode_key_hex_lower() {
        let key_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let result = try_decode_key(key_hex).unwrap();
        assert_eq!(result.as_ref(), &[0x01u8; 32]);
    }

    #[test]
    fn test_decode_key_hex_upper() {
        let key_hex = "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A";
        let result = try_decode_key(key_hex).unwrap();
        assert_eq!(result.as_ref(), &[0x0au8; 32]);
    }

    #[test]
    fn test_decode_key_base64() {
        // 32 bytes of 0x42
        let key_b64 = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";
        let result = try_decode_key(key_b64).unwrap();
        assert_eq!(result.as_ref(), &[0x42u8; 32]);
    }

    #[test]
    fn test_decode_key_base64_nopad() {
        // 32 bytes of 0x42 without padding
        let key_b64 = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
        let result = try_decode_key(key_b64).unwrap();
        assert_eq!(result.as_ref(), &[0x42u8; 32]);
    }

    #[test]
    fn test_decode_key_wrong_length() {
        let key_hex = "0101010101010101"; // Only 8 bytes
        let result = try_decode_key(key_hex);
        assert!(matches!(
            result,
            Err(DecodeError {
                position: 8,
                kind: DecodeKind::Length
            })
        ));
    }

    #[test]
    fn test_decode_key_invalid_encoding() {
        let key = "not-a-valid-key-encoding!!!";
        let result = try_decode_key(key);
        assert!(matches!(result, Err(DecodeError { .. })));
    }
}
