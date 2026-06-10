//! Results and metadata of an exchange with a roughtime server.

use std::net::SocketAddr;

use ClientError::InvalidConfiguration;
use jiff::Timestamp;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::PublicKey;

use crate::ClientError;

/// `Measurement` is the validated result and associated metadata of a Request/Response
/// exchange with a server.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Measurement {
    server: SocketAddr,
    hostname: String,
    public_key: Option<PublicKey>,
    request: Request,
    response: Response,
    response_bytes: Vec<u8>,
    rand_value: Option<[u8; 32]>,
}

/// Builder for creating `Measurement` instances.
#[derive(Default)]
pub struct MeasurementBuilder {
    server: Option<SocketAddr>,
    hostname: Option<String>,
    public_key: Option<PublicKey>,
    request: Option<Request>,
    response: Option<Response>,
    response_bytes: Option<Vec<u8>>,
    rand_value: Option<[u8; 32]>,
}

impl MeasurementBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn server(mut self, server: SocketAddr) -> Self {
        self.server = Some(server);
        self
    }

    pub fn hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn public_key(mut self, public_key: Option<PublicKey>) -> Self {
        self.public_key = public_key;
        self
    }

    pub fn request(mut self, request: Request) -> Self {
        self.request = Some(request);
        self
    }

    pub fn response(mut self, response: Response) -> Self {
        self.response = Some(response);
        self
    }

    pub fn rand_value(mut self, rand_value: Option<[u8; 32]>) -> Self {
        self.rand_value = rand_value;
        self
    }

    /// The response packet exactly as received from the server, including the
    /// "ROUGHTIM" framing. Kept verbatim because nonce chaining, malfeasance
    /// reports, and signature checks operate on the received bytes.
    pub fn response_bytes(mut self, response_bytes: Vec<u8>) -> Self {
        self.response_bytes = Some(response_bytes);
        self
    }

    pub fn build(self) -> Result<Measurement, ClientError> {
        Ok(Measurement {
            server: self
                .server
                .ok_or_else(|| InvalidConfiguration("server is required".to_string()))?,
            hostname: self.hostname.unwrap_or_else(|| "unknown".to_string()),
            public_key: self.public_key,
            request: self
                .request
                .ok_or_else(|| InvalidConfiguration("request is required".to_string()))?,
            response: self
                .response
                .ok_or_else(|| InvalidConfiguration("response is required".to_string()))?,
            response_bytes: self
                .response_bytes
                .ok_or_else(|| InvalidConfiguration("response_bytes is required".to_string()))?,
            rand_value: self.rand_value,
        })
    }
}

impl Measurement {
    /// Returns a new [MeasurementBuilder] for constructing [Measurement] instances.
    pub fn builder() -> MeasurementBuilder {
        MeasurementBuilder::new()
    }

    /// The hostname of the queried server
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// A [SocketAddr] of the server host:port
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// [PublicKey] of the server, if one was provided when the query was made
    pub fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    /// The complete roughtime [Request] sent to the server
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// The complete [Response] received from the server
    pub fn response(&self) -> &Response {
        &self.response
    }

    /// The server's time measurement, in seconds since the Unix epoch.
    ///
    /// The server's "true time" lies within `(midpoint - radius, midpoint + radius)` when
    /// the response was generated.
    pub fn midpoint(&self) -> u64 {
        self.response.srep().midp()
    }

    /// The server's time measurement, in [Timestamp] UTC.
    ///
    /// The server's "true time" lies within `(midpoint - radius, midpoint + radius)` when
    /// the response was generated.
    pub fn midpoint_datetime(&self) -> Timestamp {
        let midpoint = self.midpoint();
        Timestamp::from_second(midpoint as i64).unwrap()
    }

    /// The servers estimate of uncertainty, in seconds. The radius value represents the
    /// server's estimate in the accuracy of its midpoint.
    ///
    /// The server's "true time" lies within `(midpoint - radius, midpoint + radius)` when
    /// the response was generated.
    pub fn radius(&self) -> u32 {
        self.response.srep().radi()
    }

    /// Chained random value used in a multi-server [`MeasurementSequence`](crate::sequence::MeasurementSequence).
    pub fn rand_value(&self) -> Option<&[u8; 32]> {
        self.rand_value.as_ref()
    }

    /// The response packet exactly as received, including the "ROUGHTIM" framing
    pub fn response_bytes(&self) -> &[u8] {
        &self.response_bytes
    }
}
