//! Results and metadata of an exchange with a roughtime server.

use std::net::SocketAddr;

use jiff::Timestamp;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::PublicKey;

use crate::validation::interval;

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

impl Measurement {
    /// `response_bytes` is the response packet exactly as received from the server, including
    /// the "ROUGHTIM" framing. It is kept verbatim because nonce chaining, malfeasance reports,
    /// and signature checks operate on the received bytes.
    pub(crate) fn new(
        server: SocketAddr,
        hostname: String,
        public_key: Option<PublicKey>,
        request: Request,
        response: Response,
        response_bytes: Vec<u8>,
        rand_value: Option<[u8; 32]>,
    ) -> Self {
        Measurement {
            server,
            hostname,
            public_key,
            request,
            response,
            response_bytes,
            rand_value,
        }
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
    /// Returns `None` if the midpoint is outside the range representable by [Timestamp].
    ///
    /// The server's "true time" lies within `(midpoint - radius, midpoint + radius)` when
    /// the response was generated.
    pub fn midpoint_datetime(&self) -> Option<Timestamp> {
        let seconds = i64::try_from(self.midpoint()).ok()?;
        Timestamp::from_second(seconds).ok()
    }

    /// Earliest time consistent with this measurement (`MIDP - RADI`),
    /// saturating at zero.
    pub fn lower_bound(&self) -> u64 {
        interval(self.midpoint(), self.radius()).0
    }

    /// Latest time consistent with this measurement (`MIDP + RADI`),
    /// saturating at `u64::MAX`.
    pub fn upper_bound(&self) -> u64 {
        interval(self.midpoint(), self.radius()).1
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
    use crate::test_utils::measurement;

    #[test]
    fn unrepresentable_midpoint_datetime_is_none() {
        // jiff's Timestamp range ends near year 9999; a signed response can
        // carry any MIDP, so conversion must fail cleanly, not panic
        let measurement = measurement(300_000_000_000);
        assert!(measurement.midpoint_datetime().is_none());
    }

    #[test]
    fn sane_midpoint_datetime_is_some() {
        let measurement = measurement(1_748_359_193);
        let timestamp = measurement.midpoint_datetime().unwrap();
        assert_eq!(timestamp.as_second(), 1_748_359_193);
    }
}
