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
    /// Returns `None` when the (server-controlled) midpoint is outside the
    /// range representable by [Timestamp]; a hostile server can sign any MIDP
    /// value, so display code must not assume conversion succeeds.
    ///
    /// The server's "true time" lies within `(midpoint - radius, midpoint + radius)` when
    /// the response was generated.
    pub fn midpoint_datetime(&self) -> Option<Timestamp> {
        let seconds = i64::try_from(self.midpoint()).ok()?;
        Timestamp::from_second(seconds).ok()
    }

    /// Earliest time consistent with this measurement (`MIDP - RADI`),
    /// saturating at zero. MIDP and RADI come from the (possibly hostile)
    /// server, so the arithmetic must not underflow.
    pub fn lower_bound(&self) -> u64 {
        self.midpoint().saturating_sub(self.radius() as u64)
    }

    /// Latest time consistent with this measurement (`MIDP + RADI`),
    /// saturating at `u64::MAX`. MIDP and RADI come from the (possibly
    /// hostile) server, so the arithmetic must not overflow.
    pub fn upper_bound(&self) -> u64 {
        self.midpoint().saturating_add(self.radius() as u64)
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

#[cfg(test)]
mod tests {
    use roughenough_protocol::ToFrame;
    use roughenough_protocol::tags::PublicKey;
    use roughenough_server::test_utils::TestContext;

    use super::Measurement;

    fn create_measurement(midpoint: u64) -> Measurement {
        let mut ctx = TestContext::new(64);
        let (req, resp) = ctx.create_interaction_pair(midpoint);
        let resp_bytes = resp.as_frame_bytes().unwrap();
        let pubkey = PublicKey::from(ctx.key_source.public_key_bytes());

        Measurement::builder()
            .server("127.0.0.1:8000".parse().unwrap())
            .request(req)
            .response(resp)
            .response_bytes(resp_bytes)
            .hostname("test".to_string())
            .public_key(Some(pubkey))
            .rand_value(None)
            .build()
            .unwrap()
    }

    #[test]
    fn unrepresentable_midpoint_datetime_is_none() {
        // jiff's Timestamp range ends near year 9999; a signed response can
        // carry any MIDP, so conversion must fail cleanly, not panic
        let measurement = create_measurement(300_000_000_000);
        assert!(measurement.midpoint_datetime().is_none());
    }

    #[test]
    fn sane_midpoint_datetime_is_some() {
        let measurement = create_measurement(1_748_359_193);
        let timestamp = measurement.midpoint_datetime().unwrap();
        assert_eq!(timestamp.as_second(), 1_748_359_193);
    }
}
