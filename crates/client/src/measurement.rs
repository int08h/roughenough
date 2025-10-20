//! Results and metadata of an exchange with a roughtime server.

use std::net::SocketAddr;

use ClientError::InvalidConfiguration;
use chrono::DateTime;
use protocol::request::Request;
use protocol::response::Response;
use protocol::tags::PublicKey;

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
    rand_value: Option<[u8; 32]>,
    prior_response: Option<Response>,
}

/// Builder for creating `Measurement` instances.
#[derive(Default)]
pub struct MeasurementBuilder {
    server: Option<SocketAddr>,
    hostname: Option<String>,
    public_key: Option<PublicKey>,
    request: Option<Request>,
    response: Option<Response>,
    rand_value: Option<[u8; 32]>,
    prior_response: Option<Response>,
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

    pub fn prior_response(mut self, prior_response: Option<Response>) -> Self {
        self.prior_response = prior_response;
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
            rand_value: self.rand_value,
            prior_response: self.prior_response,
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

    /// The server's time measurement, in [DateTime] UTC.
    ///
    /// The server's "true time" lies within `(midpoint - radius, midpoint + radius)` when
    /// the response was generated.
    pub fn midpoint_datetime(&self) -> DateTime<chrono::Utc> {
        let midpoint = self.midpoint();
        DateTime::from_timestamp(midpoint as i64, 0).unwrap()
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

    /// The chained prior [`Response`] used in a multi-server [`MeasurementSequence`](crate::sequence::MeasurementSequence).
    pub fn prior_response(&self) -> Option<&Response> {
        self.prior_response.as_ref()
    }
}
