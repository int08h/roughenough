//! Observations providing proof that a server sent incorrect time.

use ReportingError::HttpError;
use data_encoding::BASE64;
use roughenough_protocol::ToFrame;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::CausalityViolation;
use crate::measurement::Measurement;

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
        let response_bytes = measurement.response().as_frame_bytes().unwrap();

        let public_key = measurement
            .public_key()
            .expect("Measurements always have a public key by construction");

        // Encode everything as base64
        ReportEntry {
            rand: measurement.rand_value().map(|r| BASE64.encode(r)),
            request: BASE64.encode(&request_bytes),
            response: BASE64.encode(&response_bytes),
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
    pub fn from_violation(violation: &CausalityViolation) -> Self {
        let measurements = [&violation.measurement_i, &violation.measurement_j];

        let responses: Vec<ReportEntry> = measurements
            .iter()
            .map(|&m| ReportEntry::from_measurement(m))
            .collect();

        MalfeasanceReport { responses }
    }

    /// POSTs the malfeasance report to the specified URL
    #[cfg(feature = "reporting")]
    pub fn submit(&self, url: &str) -> Result<(), ReportingError> {
        info!("Sending malfeasance report to {url}");

        match ureq::post(url)
            .content_type("application/json")
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
    use roughenough_protocol::FromFrame;
    use roughenough_protocol::cursor::ParseCursor;
    use roughenough_protocol::request::Request;
    use roughenough_protocol::response::Response;
    use roughenough_protocol::tags::PublicKey;

    use super::*;

    fn create_test_measurement(midpoint: u64, radius: u32) -> Measurement {
        let request = {
            let mut raw =
                include_bytes!("../../roughenough-protocol/testdata/rfc-request.071039e5").to_vec();
            let mut cursor = ParseCursor::new(&mut raw);
            Request::from_frame(&mut cursor).unwrap()
        };

        let mut response = {
            let mut raw =
                include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5")
                    .to_vec();
            let mut cursor = ParseCursor::new(&mut raw);
            Response::from_frame(&mut cursor).unwrap()
        };

        // Modify response for testing
        let mut srep = response.srep().clone();
        srep.set_midp(midpoint);
        srep.set_radi(radius);
        response.set_srep(srep);

        let public_key = PublicKey::from([0x22u8; 32]);

        Measurement::builder()
            .server("127.0.0.1:8000".parse().unwrap())
            .hostname("test".to_string())
            .public_key(Some(public_key))
            .request(request)
            .response(response)
            .rand_value(Some([0x42u8; 32]))
            .prior_response(None)
            .build()
            .unwrap()
    }

    #[test]
    fn test_report_entry_creation() {
        let measurement = create_test_measurement(1000000, 100);

        // Test entry with rand value
        let entry = ReportEntry::from_measurement(&measurement);
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
        let m1 = create_test_measurement(2000, 100);
        let m2 = create_test_measurement(1000, 100);

        let violation = CausalityViolation::new(m1, m2);
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
}
