//! Observations providing proof that a server sent incorrect time.

use ReportingError::{
    BadEntry, BrokenChain, InvalidResponse, MissingRand, NoViolation, TooFewEntries,
};
use data_encoding::BASE64;
use roughenough_common::crypto::calculate_chained_nonce;
use roughenough_protocol::ToFrame;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::PublicKey;
use roughenough_protocol::wire::FromFrame;
use serde::{Deserialize, Serialize};

use crate::measurement::Measurement;
use crate::validation::{interval, violating_pairs};
use crate::{CausalityViolation, ResponseValidator, ValidationError};

/// Media type registered for malfeasance reports (RFC 8.4.1 / 12.4.2)
pub const REPORT_MEDIA_TYPE: &str = "application/roughtime-malfeasance+json";

/// Errors that can occur during malfeasance reporting
#[derive(thiserror::Error, Debug)]
pub enum ReportingError {
    #[error("remote server: {0}")]
    HttpError(String),

    #[error("a report needs at least 2 entries to demonstrate a causality violation")]
    TooFewEntries,

    #[error("entry {index}: invalid {field}: {reason}")]
    BadEntry {
        index: usize,
        field: &'static str,
        reason: String,
    },

    #[error("entry {index}: validation failed: {source}")]
    InvalidResponse {
        index: usize,
        source: ValidationError,
    },

    #[error("entry {index}: missing a rand value")]
    MissingRand { index: usize },

    #[error("entry {index}: nonce is not H(previous response || rand)")]
    BrokenChain { index: usize },

    #[error("no causality violation demonstrated")]
    NoViolation,
}

/// A [`Request`]/[`Response`](roughenough_protocol::response::Response) observation in a [`MalfeasanceReport`].
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

    fn decode(&self, index: usize) -> Result<DecodedEntry, ReportingError> {
        let base64 = |field: &'static str, value: &str| {
            BASE64.decode(value.as_bytes()).map_err(|e| BadEntry {
                index,
                field,
                reason: e.to_string(),
            })
        };
        let wrong_length = |field: &'static str, len: usize| BadEntry {
            index,
            field,
            reason: format!("must be 32 bytes, got {len}"),
        };

        let request = base64("request", &self.request)?;
        let response = base64("response", &self.response)?;

        let key_bytes = base64("public key", &self.public_key)?;
        let public_key = PublicKey::try_from(key_bytes.as_slice())
            .map_err(|_| wrong_length("public key", key_bytes.len()))?;

        let rand = match self.rand.as_deref() {
            None => None,
            Some(value) => {
                let bytes = base64("rand", value)?;
                let rand = <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| wrong_length("rand", bytes.len()))?;
                Some(rand)
            }
        };

        Ok(DecodedEntry {
            request,
            response,
            public_key,
            rand,
        })
    }
}

struct DecodedEntry {
    request: Vec<u8>,
    response: Vec<u8>,
    public_key: PublicKey,
    rand: Option<[u8; 32]>,
}

/// Ordered [`Request`]/[`Response`](roughenough_protocol::response::Response) observations that demonstrate a violation of causality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalfeasanceReport {
    responses: Vec<ReportEntry>,
}

impl MalfeasanceReport {
    pub fn responses(&self) -> &[ReportEntry] {
        &self.responses
    }

    /// Extracts the chain of measurements that demonstrates the violation and formats
    /// them according to the RFC specification. With the `reporting` feature, `submit()` sends
    /// them to a server.
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

    /// Checks that a received report proves malfeasance: every response is valid and signed by
    /// its entry's public key, each request after the first carries the nonce chained from the
    /// previous response and its rand (RFC 8.2), and at least one pair of responses violates
    /// causality.
    pub fn verify(&self) -> Result<(), ReportingError> {
        if self.responses.len() < 2 {
            return Err(TooFewEntries);
        }

        let mut previous_response: Option<Vec<u8>> = None;
        let mut bounds = Vec::with_capacity(self.responses.len());

        for (index, entry) in self.responses.iter().enumerate() {
            let decoded = entry.decode(index)?;

            let request = Request::from_frame_bytes(&decoded.request).map_err(|e| BadEntry {
                index,
                field: "request",
                reason: e.to_string(),
            })?;

            let validator = ResponseValidator::new(Some(decoded.public_key));
            let response = validator
                .validate(&decoded.request, &decoded.response)
                .map_err(|source| InvalidResponse { index, source })?;

            // RFC 8.4.1: the first nonce is unchained, so rand "MAY be omitted"
            // from the first entry; when present it carries no meaning and is
            // accepted and ignored
            if let Some(previous) = previous_response.as_deref() {
                let rand = decoded.rand.ok_or(MissingRand { index })?;
                let expected_nonce = calculate_chained_nonce(previous, &rand);
                if *request.nonc() != expected_nonce {
                    return Err(BrokenChain { index });
                }
            }

            bounds.push(interval(response.srep().midp(), response.srep().radi()));
            previous_response = Some(decoded.response);
        }

        if violating_pairs(&bounds).is_empty() {
            return Err(NoViolation);
        }

        Ok(())
    }

    /// POSTs the malfeasance report to the specified URL
    #[cfg(feature = "reporting")]
    pub fn submit(&self, url: &str) -> Result<(), ReportingError> {
        ureq::post(url)
            .content_type(REPORT_MEDIA_TYPE)
            .send_json(self)
            .map(|_response| ())
            .map_err(|e| ReportingError::HttpError(e.to_string()))
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

    fn chained_report(midpoints: &[u64], first_rand: Option<[u8; 32]>) -> MalfeasanceReport {
        let measurements = chained_measurements(midpoints, first_rand);
        let violation = CausalityViolation::new(&measurements, 0, measurements.len() - 1);
        MalfeasanceReport::from_violation(&violation)
    }

    fn violating_report() -> MalfeasanceReport {
        chained_report(&[BASE_TIME + 2_000_000, BASE_TIME], None)
    }

    #[test]
    fn chained_report_without_violation_is_rejected() {
        let base = BASE_TIME;
        let report = chained_report(&[base, base + 1_000, base + 2_000], None);

        assert!(matches!(report.verify(), Err(NoViolation)));
    }

    #[test]
    fn chained_report_with_violation_is_accepted() {
        let base = BASE_TIME;
        let report = chained_report(&[base + 2_000_000, base + 1_000_000, base], None);

        report
            .verify()
            .expect("violating chained report must verify");
    }

    #[test]
    fn first_entry_carrying_rand_is_accepted() {
        let base = BASE_TIME;

        // RFC 8.4.1: rand MAY be omitted from the first entry; carrying one
        // is not an error
        let report = chained_report(&[base + 2_000_000, base], Some([0x77u8; 32]));
        assert!(report.responses()[0].rand().is_some());

        report
            .verify()
            .expect("first-entry rand must be accepted and ignored");
    }

    #[test]
    fn report_with_draft_and_version_one_entries_is_accepted() {
        use roughenough_common::crypto::random_bytes;
        use roughenough_protocol::response::Response;
        use roughenough_protocol::tags::ProtocolVersion;
        use roughenough_server::test_utils::TestContext;

        // Entry 0: a real draft 0x8000000c exchange (MIDP 2025-05-22)
        let draft_request_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-request.071039e5").to_vec();
        let draft_response_bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();
        let draft_key = BASE64
            .decode(b"AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=")
            .unwrap();

        let draft_request = Request::from_frame_bytes(&draft_request_bytes).unwrap();
        let draft_response = Response::from_frame_bytes(&draft_response_bytes).unwrap();
        assert_eq!(*draft_response.srep().ver(), ProtocolVersion::DRAFT);

        let draft_measurement = Measurement::new(
            "127.0.0.1:2002".parse().unwrap(),
            "draft".to_string(),
            Some(PublicKey::try_from(draft_key.as_slice()).unwrap()),
            draft_request,
            draft_response,
            draft_response_bytes.clone(),
            None,
        );

        // Entry 1: a version 1 exchange chained to entry 0 whose MIDP is
        // earlier than entry 0's
        let rand = random_bytes::<32>();
        let nonce = calculate_chained_nonce(&draft_response_bytes, &rand);
        let mut ctx = TestContext::new_at(1, BASE_TIME);
        let (request, response) = ctx.create_interaction_pair_with_nonce(BASE_TIME, &nonce);
        assert_eq!(*response.srep().ver(), ProtocolVersion::RFC);

        let rfc_measurement = Measurement::new(
            "127.0.0.1:5319".parse().unwrap(),
            "rfc".to_string(),
            Some(ctx.key_source.public_key()),
            request,
            response.clone(),
            response.as_frame_bytes().unwrap(),
            Some(rand),
        );

        let measurements = vec![draft_measurement, rfc_measurement];
        let violation = CausalityViolation::new(&measurements, 0, 1);
        let report = MalfeasanceReport::from_violation(&violation);

        report
            .verify()
            .expect("draft and version 1 entries must verify");
    }

    #[test]
    fn every_found_violation_yields_a_verifiable_report() {
        let base = BASE_TIME;

        // Measurement 0 claims a time far ahead of measurements 1 and 2, so every
        // pair -- (0,1), (0,2), and (1,2) -- violates causality
        let measurements = chained_measurements(&[base + 2_000_000, base + 1_000_000, base], None);

        let violations = CausalityViolation::find(&measurements);
        assert_eq!(violations.len(), 3, "all three pairs violate causality");

        for violation in &violations {
            let report = MalfeasanceReport::from_violation(violation);

            // Verify what a reporting server would receive, not the in-memory report
            let json = serde_json::to_string(&report).unwrap();
            let received: MalfeasanceReport = serde_json::from_str(&json).unwrap();

            received.verify().unwrap_or_else(|e| {
                panic!(
                    "report for violating pair ({}, {}) was rejected: {e}",
                    violation.index_i(),
                    violation.index_j()
                )
            });
        }
    }

    #[test]
    fn report_spanning_an_intermediate_measurement_verifies() {
        let base = BASE_TIME;

        // Only the (0, 2) pair violates: measurement 1 is consistent with both
        // neighbors
        let measurements = chained_measurements(&[base + 15, base + 8, base], None);

        let violations = CausalityViolation::find(&measurements);
        assert_eq!(violations.len(), 1, "only the (0, 2) pair violates");
        assert_eq!(violations[0].index_i(), 0);
        assert_eq!(violations[0].index_j(), 2);

        let report = MalfeasanceReport::from_violation(&violations[0]);
        assert_eq!(report.responses().len(), 3);

        assert_eq!(
            report.responses()[1].rand().unwrap(),
            BASE64.encode(measurements[1].rand_value().unwrap())
        );

        report
            .verify()
            .expect("chained report spanning three measurements must verify");
    }

    #[test]
    fn single_entry_is_too_few() {
        let measurements = chained_measurements(&[BASE_TIME], None);
        let report = MalfeasanceReport {
            responses: vec![ReportEntry::from_measurement(&measurements[0])],
        };

        assert!(matches!(report.verify(), Err(TooFewEntries)));
    }

    #[test]
    fn bad_base64_is_bad_entry() {
        let mut report = violating_report();
        report.responses[1].response = "not base64!".to_string();

        assert!(matches!(
            report.verify(),
            Err(BadEntry {
                index: 1,
                field: "response",
                ..
            })
        ));
    }

    #[test]
    fn short_public_key_is_bad_entry() {
        let mut report = violating_report();
        report.responses[0].public_key = BASE64.encode(&[0u8; 16]);

        assert!(matches!(
            report.verify(),
            Err(BadEntry {
                index: 0,
                field: "public key",
                ..
            })
        ));
    }

    #[test]
    fn missing_rand_after_first_entry_is_rejected() {
        let mut report = violating_report();
        report.responses[1].rand = None;

        assert!(matches!(report.verify(), Err(MissingRand { index: 1 })));
    }

    #[test]
    fn wrong_rand_breaks_chain() {
        let mut report = violating_report();
        report.responses[1].rand = Some(BASE64.encode(&[0u8; 32]));

        assert!(matches!(report.verify(), Err(BrokenChain { index: 1 })));
    }

    #[test]
    fn tampered_response_fails_validation() {
        use roughenough_protocol::header::find_value_range;
        use roughenough_protocol::tag::Tag;
        use roughenough_protocol::wire::FRAME_OVERHEAD;

        let mut report = violating_report();

        // Entry 1's response does not feed any nonce, so only its validation can fail
        let mut response = BASE64
            .decode(report.responses[1].response.as_bytes())
            .unwrap();
        let srep = find_value_range(&response[FRAME_OVERHEAD..], &[Tag::SREP]).unwrap();
        response[FRAME_OVERHEAD + srep.end - 1] ^= 0xff;
        report.responses[1].response = BASE64.encode(&response);

        assert!(matches!(
            report.verify(),
            Err(InvalidResponse { index: 1, .. })
        ));
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
