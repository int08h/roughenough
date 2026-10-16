//! Observations providing proof that a server sent incorrect time.

use ReportingError::HttpError;
use data_encoding::BASE64;
use roughenough_protocol::ToFrame;
use serde::{Deserialize, Serialize};
#[cfg(feature = "reporting")]
use tracing::error;
use tracing::info;

use crate::CausalityViolation;
use crate::measurement::Measurement;

/// Media type registered for malfeasance reports (RFC 8.4.1 / 12.4.2)
pub const REPORT_MEDIA_TYPE: &str = "application/roughtime-malfeasance+json";

/// Errors that can occur during malfeasance reporting
#[derive(thiserror::Error, Debug)]
pub enum ReportingError {
    #[error("{0}")]
    SerializationError(#[from] roughenough_protocol::error::Error),

    #[error("remote server: {0}")]
    HttpError(String),
}

/// A [`Request`](roughenough_protocol::request::Request)/[`Response`](roughenough_protocol::response::Response) observation in a [`MalfeasanceReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEntry {
    /// Base-64 encoded 32-byte random value used to generate the request nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    rand: Option<String>,

    /// Base64-encoded request bytes (including framing magic value and length)
    request: String,

    /// Base64-encoded response bytes (including framing magic value and length)
    response: String,

    /// Base64-encoded long-term public key expected from the server
    #[serde(rename = "publicKey")]
    public_key: String,
}

impl ReportEntry {
    /// the rand value if present
    pub fn rand(&self) -> Option<&str> {
        self.rand.as_deref()
    }

    /// base64-encoded request
    pub fn request(&self) -> &str {
        &self.request
    }

    /// base64-encoded response
    pub fn response(&self) -> &str {
        &self.response
    }

    /// base64-encoded public key
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Creates a report entry from a measurement
    fn from_measurement(measurement: &Measurement) -> Self {
        let request_bytes = measurement.request().as_frame_bytes().unwrap();

        let public_key = measurement
            .public_key()
            .expect("Measurements always have a public key by construction");

        // Encode everything as base64. The response is reported exactly as it
        // was received from the server.
        ReportEntry {
            rand: measurement.rand_value().map(|r| BASE64.encode(r)),
            request: BASE64.encode(&request_bytes),
            response: BASE64.encode(measurement.response_bytes()),
            public_key: BASE64.encode(public_key.as_ref()),
        }
    }
}

/// Ordered [`Request`](roughenough_protocol::request::Request)/[`Response`](roughenough_protocol::response::Response) observations that demonstrate a violation of causality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalfeasanceReport {
    responses: Vec<ReportEntry>,
}

impl MalfeasanceReport {
    pub fn responses(&self) -> &[ReportEntry] {
        &self.responses
    }

    /// Extracts the chain of measurements that demonstrates the violation and formats
    /// them according to the RFC specification. Use `submit()` to send them to a server.
    ///
    /// The report carries the violation's full measurement chain, in the order
    /// performed (RFC 8.4.1).
    pub fn from_violation(violation: &CausalityViolation) -> Self {
        let responses: Vec<ReportEntry> = violation
            .chain()
            .iter()
            .map(ReportEntry::from_measurement)
            .collect();

        MalfeasanceReport { responses }
    }

    /// POSTs the malfeasance report to the specified URL
    #[cfg(feature = "reporting")]
    pub fn submit(&self, url: &str) -> Result<(), ReportingError> {
        info!("Sending malfeasance report to {url}");

        match ureq::post(url)
            .content_type(REPORT_MEDIA_TYPE)
            .send_json(self)
        {
            Ok(_response) => {
                info!("Successfully sent malfeasance report");
                Ok(())
            }
            Err(e) => {
                error!("failed to submit report: {e}");
                Err(HttpError(e.to_string()))
            }
        }
    }

    #[cfg(not(feature = "reporting"))]
    pub fn submit(&self, _url: &str) -> Result<(), ReportingError> {
        info!("Report submission is disabled. Recompile with the 'reporting' feature to enable.");
        Err(HttpError("Reporting is disabled".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{BASE_TIME, chained_measurements};

    #[test]
    fn test_report_entry_creation() {
        let measurements = chained_measurements(&[BASE_TIME + 2000, BASE_TIME + 1000], None);

        // Entry 0 has no rand; entry 1 carries the rand that chained its nonce
        let entry = ReportEntry::from_measurement(&measurements[1]);
        assert!(entry.rand.is_some());
        assert!(!entry.request.is_empty());
        assert!(!entry.response.is_empty());
        assert!(!entry.public_key.is_empty());

        // Verify base64 encoding
        let decoded_key = BASE64.decode(entry.public_key.as_bytes()).unwrap();
        assert_eq!(decoded_key.len(), 32);
    }

    #[test]
    fn test_json_serialization() {
        let measurements = chained_measurements(&[BASE_TIME + 2000, BASE_TIME + 1000], None);

        let violation = CausalityViolation::new(&measurements, 0, 1);
        let report = MalfeasanceReport::from_violation(&violation);

        let json = serde_json::to_string_pretty(&report).unwrap();

        // Verify JSON structure
        assert!(json.contains("\"responses\""));
        assert!(json.contains("\"request\""));
        assert!(json.contains("\"response\""));
        assert!(json.contains("\"publicKey\""));

        // Verify it's valid JSON
        let _parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn violation_between_first_and_third_reports_full_chain() {
        let base = BASE_TIME;
        // measurement 0 claims a time far ahead of measurement 2
        let measurements = chained_measurements(&[base + 2_000_000, base + 1_000_000, base], None);

        let violation = CausalityViolation::new(&measurements, 0, 2);
        let report = MalfeasanceReport::from_violation(&violation);

        // All three measurements appear, in the order performed
        assert_eq!(report.responses().len(), 3);
        for (entry, m) in report.responses().iter().zip(&measurements) {
            let request_bytes = m.request().as_frame_bytes().unwrap();
            assert_eq!(entry.request(), BASE64.encode(&request_bytes));
            assert_eq!(entry.response(), BASE64.encode(m.response_bytes()));
        }

        // First entry's nonce was unchained: no rand. Later entries carry the
        // rand used to derive their nonce from the previous response.
        assert!(report.responses()[0].rand().is_none());
        for (entry, m) in report.responses().iter().zip(&measurements).skip(1) {
            let expected = BASE64.encode(m.rand_value().unwrap());
            assert_eq!(entry.rand().unwrap(), expected);
        }
    }

    #[cfg(feature = "reporting")]
    #[test]
    fn submit_sends_registered_media_type() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use crate::reporting::REPORT_MEDIA_TYPE;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Minimal HTTP endpoint: capture the request head, drain the body so
        // the client's write completes, then answer 200
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];

            let head_end = loop {
                let n = stream.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                assert!(n > 0, "connection closed before headers completed");
            };

            let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
            let content_length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .expect("request must declare content-length")
                .trim()
                .parse()
                .unwrap();

            while buf.len() < head_end + content_length {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "connection closed before body completed");
                buf.extend_from_slice(&chunk[..n]);
            }

            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .unwrap();
            head
        });

        let measurements = chained_measurements(&[BASE_TIME + 2000, BASE_TIME + 1000], None);
        let violation = CausalityViolation::new(&measurements, 0, 1);
        let report = MalfeasanceReport::from_violation(&violation);

        report.submit(&format!("http://{addr}/reports")).unwrap();

        let head = handle.join().unwrap();
        assert!(
            head.contains(&format!("content-type: {REPORT_MEDIA_TYPE}")),
            "request head lacks the registered media type: {head}"
        );
    }
}
