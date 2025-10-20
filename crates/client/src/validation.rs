//! Validate Responses from Roughtime servers.
//!
//! * Use [`ResponseValidator::validate`] to validate an individual [`Response`], or
//! * [`ResponseValidator::validate_causality`]
//!   to inspect the results of a [`MeasurementSequence`](crate::sequence::MeasurementSequence).

use aws_lc_rs::signature;
use aws_lc_rs::signature::UnparsedPublicKey;
use data_encoding::HEXLOWER;
use merkle::MerkleTree;
use protocol::cursor::ParseCursor;
use protocol::response::Response;
use protocol::tags::PublicKey;
use protocol::wire::ToWire;

use crate::measurement::Measurement;

/// Reasons a response's time may be invalid
#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    #[error("The returned midpoint time is invalid: {0}")]
    InvalidMidpoint(String),

    #[error("Bad signature: {0}")]
    BadSignature(String),

    #[error("Invalid Merkle proof: {0}")]
    FailedProof(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(#[from] protocol::error::Error),
}

/// An instance of causality constraints being violated. For this pair of responses `(i, j)`
/// where `i` was received before `j`, the lower bound (`MIDP_i - RADI_i`) is greater than the
/// upper bound (`MIDP_j + RADI_j`).
#[derive(Debug)]
pub struct CausalityViolation {
    pub measurement_i: Measurement,
    pub measurement_j: Measurement,
    pub lower_bound_i: u64,
    pub upper_bound_j: u64,
}

// TODO(stuart) right now CausalityViolation only supports two measurements. It needs to be
// extended to support arbitrary number of measurements, and somehow capture/note the relationship
// between the measurements and the violation.
impl CausalityViolation {
    pub fn new(measurement_i: Measurement, measurement_j: Measurement) -> Self {
        let lower_bound_i = measurement_i.midpoint() - measurement_i.radius() as u64;
        let upper_bound_j = measurement_j.midpoint() + measurement_j.radius() as u64;
        assert!(
            lower_bound_i > upper_bound_j,
            "(MIDP_i - RADI_i > MIDP_j + RADI_j) does not hold"
        );

        Self {
            measurement_i,
            measurement_j,
            lower_bound_i,
            upper_bound_j,
        }
    }
}

/// Validate the [`Response`]s from roughtime servers.
///
/// The [`validate`](Self::validate) method validates individual responses. While the [`validate_causality`](Self::validate_causality)
/// method inspects the results of a [`MeasurementSequence`](crate::sequence::MeasurementSequence).
#[derive(Debug, Default)]
pub struct ResponseValidator {
    pub_key: Option<UnparsedPublicKey<[u8; 32]>>,
}

impl ResponseValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_key(pub_key: PublicKey) -> Self {
        let key_bytes: [u8; 32] = pub_key
            .as_ref()
            .try_into()
            .expect("expected a valid 32-byte public key");

        let key = UnparsedPublicKey::new(&signature::ED25519, key_bytes);

        Self { pub_key: Some(key) }
    }

    /// Validate a response. Validity of a response does not prove that the timestamp's value in
    /// the response is correct, but merely that the server represents it signed the timestamp
    /// and computed its signature during the time interval (MIDP-RADI, MIDP+RADI).
    pub fn validate(&self, request: &[u8], response: &Response) -> Result<u64, ValidationError> {
        // RFC section 5.4. Validity of Response:
        //   "A client MUST check the following properties when it receives a
        //   response. We assume the long-term server public key is known to the
        //   client through other means."

        // The signature in CERT was made with the long-term key of the server.
        if self.pub_key.is_some() {
            self.check_dele_signature(response)?;
        }

        // The MIDP timestamp lies in the interval specified by the MINT and MAXT timestamps.
        self.check_midpoint(response)?;

        // The INDX and PATH values prove a hash value derived from the request packet was included
        // in the Merkle tree ROOT
        self.check_merkle_proof(request, response)?;

        // The signature of SREP in SIG validates with the public key in DELE.
        self.check_srep_signature(response)?;

        let midpoint = response.srep().midp();
        Ok(midpoint)
    }

    fn check_dele_signature(&self, response: &Response) -> Result<(), ValidationError> {
        let dele = response.cert().dele();
        let prefix = response.srep().ver().dele_prefix();

        let mut cert_bytes = vec![0u8; prefix.len() + dele.wire_size()];
        cert_bytes[..prefix.len()].copy_from_slice(prefix);
        let mut cursor = ParseCursor::new(&mut cert_bytes[prefix.len()..]);
        dele.to_wire(&mut cursor)?;

        let signature = response.cert().sig();

        match self
            .pub_key
            .unwrap()
            .verify(&cert_bytes, signature.as_ref())
        {
            Ok(_) => Ok(()),
            Err(_) => Err(ValidationError::BadSignature(
                "signature on DELE is invalid".to_string(),
            )),
        }
    }

    fn check_srep_signature(&self, response: &Response) -> Result<(), ValidationError> {
        let srep = response.srep();
        let prefix = srep.ver().srep_prefix();

        let mut srep_bytes = vec![0u8; prefix.len() + srep.wire_size()];
        srep_bytes[..prefix.len()].copy_from_slice(prefix);
        let mut cursor = ParseCursor::new(&mut srep_bytes[prefix.len()..]);
        srep.to_wire(&mut cursor)?;

        let dele = response.cert().dele();
        let pubk = UnparsedPublicKey::new(&signature::ED25519, dele.pubk().as_ref());

        match pubk.verify(&srep_bytes, response.sig().as_ref()) {
            Ok(_) => Ok(()),
            Err(_) => {
                let msg = format!(
                    "signature {:?} by {:?} on SREP is invalid",
                    response.sig(),
                    dele.pubk()
                );
                Err(ValidationError::BadSignature(msg))
            }
        }
    }

    fn check_merkle_proof(
        &self,
        request: &[u8],
        response: &Response,
    ) -> Result<(), ValidationError> {
        let merkle_path = response.path();
        let index = response.indx() as usize;

        let tree = MerkleTree::new();
        let computed_root = tree.root_from_paths(index, request, merkle_path);
        let response_root = response.srep().root().as_ref();

        if computed_root != *response_root {
            let msg = format!(
                "Nonce is not present in the response's merkle tree: computed {} != ROOT {}",
                HEXLOWER.encode(&computed_root),
                HEXLOWER.encode(response_root)
            );
            return Err(ValidationError::FailedProof(msg));
        }

        Ok(())
    }

    fn check_midpoint(&self, response: &Response) -> Result<(), ValidationError> {
        let midpoint = response.srep().midp();
        let mint = response.cert().dele().mint();
        let maxt = response.cert().dele().maxt();

        if midpoint < mint {
            let msg = format!("midpoint ({midpoint}) is *before* delegation span ({mint}, {maxt})");
            return Err(ValidationError::InvalidMidpoint(msg));
        }
        if midpoint > maxt {
            let msg = format!("midpoint ({midpoint}) is *after* delegation span ({mint}, {maxt})");
            return Err(ValidationError::InvalidMidpoint(msg));
        }

        Ok(())
    }

    /// Validate causality constraints across a set of measurements. For each pair of responses
    /// `(i, j)` where `i` was received before `j`, checks that
    /// `MIDP_i - RADI_i <= MIDP_j + RADI_j`. Returns a list of violations if any are found,
    /// otherwise returns an empty list.
    pub fn validate_causality(measurements: &[Measurement]) -> Vec<CausalityViolation> {
        if measurements.len() < 2 {
            return Vec::new();
        }

        let mut violations = Vec::new();

        for i in 0..measurements.len() {
            for j in (i + 1)..measurements.len() {
                let lower_bound_i = measurements[i].midpoint() - measurements[i].radius() as u64;
                let upper_bound_j = measurements[j].midpoint() + measurements[j].radius() as u64;

                if lower_bound_i > upper_bound_j {
                    violations.push(CausalityViolation::new(
                        measurements[i].clone(),
                        measurements[j].clone(),
                    ));
                }
            }
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use ValidationError::{BadSignature, InvalidMidpoint};
    use data_encoding::BASE64;
    use protocol::cursor::ParseCursor;
    use protocol::response::Response;
    use protocol::tags::PublicKey;
    use protocol::wire::FromFrame;

    use crate::validation::{ResponseValidator, ValidationError};

    #[test]
    fn dele_signature_is_validated() {
        let pub_key = BASE64
            .decode(b"AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=")
            .unwrap();

        let mut msg_bytes =
            include_bytes!("../../protocol/testdata/rfc-response.071039e5").to_vec();

        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();
        let validator = ResponseValidator::new_with_key(PublicKey::from(pub_key.as_slice()));

        validator.check_dele_signature(&response).unwrap();
    }

    #[test]
    fn srep_signature_is_validated() {
        let mut msg_bytes =
            include_bytes!("../../protocol/testdata/rfc-response.071039e5").to_vec();

        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();
        let validator = ResponseValidator::new();

        validator.check_srep_signature(&response).unwrap();
    }

    #[test]
    fn corrupt_dele_signature_is_detected() {
        let pub_key = BASE64
            .decode(b"AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=")
            .unwrap();

        let mut msg_bytes =
            include_bytes!("../../protocol/testdata/rfc-response.071039e5").to_vec();

        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let mut response = Response::from_frame(&mut cursor).unwrap();

        let mut cert_copy = response.cert().clone();
        let mut dele_copy = cert_copy.dele().clone();

        // Change the value of the DELE.MINT field
        dele_copy.set_mint(dele_copy.mint() + 1);
        cert_copy.set_dele(dele_copy);
        response.set_cert(cert_copy);

        let validator = ResponseValidator::new_with_key(PublicKey::from(pub_key.as_slice()));

        match validator.check_dele_signature(&response) {
            Err(BadSignature(msg)) => assert!(msg.contains("DELE")), // ok, expected failure
            Err(e) => panic!("expected BadSignature, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn corrupt_srep_signature_is_detected() {
        let mut msg_bytes =
            include_bytes!("../../protocol/testdata/rfc-response.071039e5").to_vec();

        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let mut response = Response::from_frame(&mut cursor).unwrap();

        let mut srep_copy = response.srep().clone();

        // Change the value of the MIDP
        srep_copy.set_midp(srep_copy.midp() + 1);
        response.set_srep(srep_copy);

        let validator = ResponseValidator::new();

        match validator.check_srep_signature(&response) {
            Err(BadSignature(msg)) => assert!(msg.contains("SREP")), // ok, expected failure
            Err(e) => panic!("expected BadSignature, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn midpoint_is_validated() {
        let validator = ResponseValidator::new();

        let mut msg_bytes =
            include_bytes!("../../protocol/testdata/rfc-response.071039e5").to_vec();
        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response1 = Response::from_frame(&mut cursor).unwrap();

        // Happy-path should pass
        validator.check_midpoint(&response1).unwrap();
    }

    #[test]
    fn midpoint_outside_of_dele_bounds_is_detected() {
        let validator = ResponseValidator::new();

        let mut msg_bytes =
            include_bytes!("../../protocol/testdata/rfc-response.071039e5").to_vec();
        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();

        //
        // Change request so that the midpoint is *before* MINT
        //
        let mut response1 = response.clone();
        let mut cert1 = response1.cert().clone();
        let mut dele1 = cert1.dele().clone();

        dele1.set_mint(response1.srep().midp() + 1000);
        cert1.set_dele(dele1);
        response1.set_cert(cert1);

        match validator.check_midpoint(&response1) {
            Err(InvalidMidpoint(msg)) => assert!(msg.contains("before")),
            Err(e) => panic!("expected InvalidMidpoint, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }

        //
        // Other direction: request midpoint is *after* MAXT
        //
        let mut response2 = response.clone();
        let mut cert2 = response2.cert().clone();
        let mut dele2 = cert2.dele().clone();

        dele2.set_maxt(response2.srep().midp() - 1000);
        cert2.set_dele(dele2);
        response2.set_cert(cert2);

        match validator.check_midpoint(&response2) {
            Err(InvalidMidpoint(msg)) => assert!(msg.contains("after")),
            Err(e) => panic!("expected InvalidMidpoint, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn merkle_proof_with_wrong_nonce_is_detected() {
        use protocol::ToWire;
        use protocol::request::RequestPlain;
        use protocol::tags::Nonce;

        let validator = ResponseValidator::new();

        let nonce = Nonce::from([0x42u8; 32]);
        let request = RequestPlain::new(&nonce);
        let request_bytes = request.as_bytes().unwrap();

        let mut msg_bytes =
            include_bytes!("../../protocol/testdata/rfc-response.071039e5").to_vec();
        let mut cursor = ParseCursor::new(&mut msg_bytes);
        let response = Response::from_frame(&mut cursor).unwrap();

        // This should fail because the response was for a different nonce
        match validator.check_merkle_proof(&request_bytes, &response) {
            Err(ValidationError::FailedProof(_)) => {} // ok, expected failure
            Err(e) => panic!("expected ValidationError::FailedProof, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }
}

#[cfg(test)]
mod causality {
    use server::test_utils::TestContext;

    use super::*;

    fn create_measurement(midpoint: u64) -> Measurement {
        let mut test_context = TestContext::new(64);
        let (req, resp) = test_context.create_interaction_pair(midpoint);
        let pubkey = PublicKey::from(test_context.key_source.public_key_bytes());

        Measurement::builder()
            .server("127.0.0.1:8000".parse().unwrap())
            .request(req)
            .response(resp)
            .hostname("testing1234".to_string())
            .public_key(Some(pubkey))
            .prior_response(None)
            .rand_value(None)
            .build()
            .unwrap()
    }

    #[test]
    fn empty() {
        let measurements = vec![];
        let result = ResponseValidator::validate_causality(&measurements);
        assert!(
            result.is_empty(),
            "Empty measurements should return no violations"
        );
    }

    #[test]
    fn single() {
        let measurements = vec![create_measurement(1000000)];
        let result = ResponseValidator::validate_causality(&measurements);
        assert!(
            result.is_empty(),
            "Single measurement should return no violations"
        );
    }

    #[test]
    fn valid_sequence() {
        // Create causally consistent measurements
        // M0: [ 995, 1005]
        // M1: [1995, 2005]
        // M2: [2995, 3005]
        let measurements = vec![
            create_measurement(1000),
            create_measurement(2000),
            create_measurement(3000),
        ];

        let result = ResponseValidator::validate_causality(&measurements);
        assert!(
            result.is_empty(),
            "Valid causal sequence should return no violations"
        );
    }

    #[test]
    fn invalid_sequence() {
        // Create causally inconsistent measurements
        // M0: [1995, 2005]
        // M1: [995, 1005]
        // Violation: 1995 > 1005
        let measurements = vec![create_measurement(2000), create_measurement(1000)];

        let violations = ResponseValidator::validate_causality(&measurements);
        assert!(
            !violations.is_empty(),
            "Invalid sequence should return some violations"
        );

        assert_eq!(violations.len(), 1, "Should have exactly one violation");

        let v = &violations[0];
        assert_eq!(v.lower_bound_i, 1995);
        assert_eq!(v.upper_bound_j, 1005);
    }

    #[test]
    fn multiple_violations() {
        // Create multiple violations
        // M0: [2995, 3005]
        // M1: [ 995, 1005] - violates with M0
        // M2: [1000, 1010] - violates with M0
        let measurements = vec![
            create_measurement(3000),
            create_measurement(1000),
            create_measurement(1005),
        ];

        let violations = ResponseValidator::validate_causality(&measurements);
        assert!(!violations.is_empty(), "Should have violations");

        assert_eq!(violations.len(), 2, "Should have exactly two violations");

        // Check first violation (0,1)
        assert_eq!(violations[0].lower_bound_i, 2995);
        assert_eq!(violations[0].upper_bound_j, 1005);

        // Check second violation (0,2)
        assert_eq!(violations[1].lower_bound_i, 2995);
        assert_eq!(violations[1].upper_bound_j, 1010);
    }

    #[test]
    fn edge_case() {
        // Test exact boundary condition: lower_bound_i == upper_bound_j
        // M0: [995, 1005]
        // M1: [985, 995]
        // This should be valid (995 <= 995)
        let measurements = vec![create_measurement(1000), create_measurement(990)];

        let result = ResponseValidator::validate_causality(&measurements);
        assert!(result.is_empty(), "Exact boundary should be valid");
    }
}
