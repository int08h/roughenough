//! Validate Responses from Roughtime servers.
//!
//! * Use [`ResponseValidator::validate`] to validate an individual [`Response`], or
//! * [`CausalityViolation::find`]
//!   to inspect the results of a [`MeasurementSequence`](crate::sequence::MeasurementSequence).

use data_encoding::HEXLOWER;
use roughenough_common::crypto::verify_with_context;
use roughenough_merkle::root_from_paths;
use roughenough_protocol::header::find_value_range;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tag::Tag;
use roughenough_protocol::tags::{ProtocolVersion, PublicKey};
use roughenough_protocol::wire::{FRAME_OVERHEAD, FromFrame};

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
    InvalidMessage(#[from] roughenough_protocol::error::Error),

    #[error("Response version {0:?} was not offered in the request")]
    UnofferedVersion(ProtocolVersion),

    #[error("Response VERS {vers:?} does not contain its VER {ver:?} (RFC 5.2.5)")]
    VerNotInVers {
        ver: ProtocolVersion,
        vers: Vec<ProtocolVersion>,
    },
}

/// `(MIDP - RADI, MIDP + RADI)`, saturating: both values are wire-derived.
pub(crate) fn interval(midp: u64, radi: u32) -> (u64, u64) {
    (
        midp.saturating_sub(radi as u64),
        midp.saturating_add(radi as u64),
    )
}

/// Index pairs `(i, j)`, `i < j`, where the earliest time of `i` is after the latest time of
/// `j`. `bounds` holds each measurement's [`interval`], in the order performed.
pub(crate) fn violating_pairs(bounds: &[(u64, u64)]) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();

    for (i, &(lower_i, _)) in bounds.iter().enumerate() {
        for (j, &(_, upper_j)) in bounds.iter().enumerate().skip(i + 1) {
            if lower_i > upper_j {
                pairs.push((i, j));
            }
        }
    }

    pairs
}

/// An instance of causality constraints being violated. For the pair of measurements
/// `(i, j)` where `i` was received before `j`, the lower bound (`MIDP_i - RADI_i`) is
/// greater than the upper bound (`MIDP_j + RADI_j`).
///
/// Carries the full measurement chain from the first measurement through `j`: a
/// malfeasance report must reproduce the contiguous nonce chain (RFC 8.4.1), since the
/// verifier recomputes each nonce as `H(prior_response || rand)`. Dropping measurements
/// before or between the violating pair would break that recomputation.
#[derive(Debug)]
pub struct CausalityViolation {
    chain: Vec<Measurement>,
    index_i: usize,
    index_j: usize,
}

impl CausalityViolation {
    /// Find every pair of `measurements` that violates causality. For each pair `(i, j)`,
    /// where `i` was received before `j`, checks that `MIDP_i - RADI_i <= MIDP_j + RADI_j`.
    /// Returns an empty list if all pairs are consistent.
    pub fn find(measurements: &[Measurement]) -> Vec<CausalityViolation> {
        let bounds: Vec<(u64, u64)> = measurements
            .iter()
            .map(|m| (m.lower_bound(), m.upper_bound()))
            .collect();

        violating_pairs(&bounds)
            .into_iter()
            .map(|(i, j)| Self::new(measurements, i, j))
            .collect()
    }

    /// The violating pair `(index_i, index_j)` of `measurements`, with `index_i < index_j`.
    pub fn new(measurements: &[Measurement], index_i: usize, index_j: usize) -> Self {
        debug_assert!(index_i < index_j);

        Self {
            chain: measurements[..=index_j].to_vec(),
            index_i,
            index_j,
        }
    }

    /// Measurements 0 through `j` inclusive, in the order performed
    pub fn chain(&self) -> &[Measurement] {
        &self.chain
    }

    /// Index of the earlier measurement of the violating pair
    pub fn index_i(&self) -> usize {
        self.index_i
    }

    /// Index of the later measurement of the violating pair
    pub fn index_j(&self) -> usize {
        self.index_j
    }

    /// The earlier measurement of the violating pair
    pub fn measurement_i(&self) -> &Measurement {
        &self.chain[self.index_i]
    }

    /// The later measurement of the violating pair
    pub fn measurement_j(&self) -> &Measurement {
        &self.chain[self.index_j]
    }

    /// `MIDP_i - RADI_i` (saturating)
    pub fn lower_bound_i(&self) -> u64 {
        self.measurement_i().lower_bound()
    }

    /// `MIDP_j + RADI_j` (saturating)
    pub fn upper_bound_j(&self) -> u64 {
        self.measurement_j().upper_bound()
    }
}

/// Validate the [`Response`]s from roughtime servers.
///
/// See [`CausalityViolation::find`] to inspect the results of a
/// [`MeasurementSequence`](crate::sequence::MeasurementSequence).
#[derive(Debug, Default)]
pub struct ResponseValidator {
    pub_key: Option<PublicKey>,
}

impl ResponseValidator {
    /// With `pub_key` (the server's long-term key) the DELE signature is verified as well;
    /// without it, the response is only self-consistent.
    pub fn new(pub_key: Option<PublicKey>) -> Self {
        Self { pub_key }
    }

    /// Parse and validate a response. Validity of a response does not prove that the
    /// timestamp's value in the response is correct, but merely that the server represents it
    /// signed the timestamp and computed its signature during the time interval
    /// (MIDP-RADI, MIDP+RADI).
    ///
    /// `request_bytes` is the framed request as sent, and `response_bytes` the response packet
    /// exactly as received (including the "ROUGHTIM" framing).
    pub fn validate(
        &self,
        request_bytes: &[u8],
        response_bytes: &[u8],
    ) -> Result<Response, ValidationError> {
        let request = Request::from_frame_bytes(request_bytes)?;
        let response = Response::from_frame_bytes(response_bytes)?;

        // RFC 7: a response with a version number not in the request is
        // invalid. Checked first because the version selects the signature
        // context strings.
        check_version(&request, &response)?;

        // RFC section 5.4. Validity of Response:
        //   "A client MUST check the following properties when it receives a
        //   response. We assume the long-term server public key is known to the
        //   client through other means."

        // The signature in CERT was made with the long-term key of the server.
        if let Some(pub_key) = &self.pub_key {
            check_dele_signature(pub_key, response_bytes, &response)?;
        }

        // The MIDP timestamp lies in the interval specified by the MINT and MAXT timestamps.
        check_midpoint(&response)?;

        // The INDX and PATH values prove a hash value derived from the request packet was included
        // in the Merkle tree ROOT
        check_merkle_proof(request_bytes, &response)?;

        // The signature of SREP in SIG validates with the public key in DELE.
        check_srep_signature(response_bytes, &response)?;

        Ok(response)
    }
}

/// Slice the value of nested `path` tags out of a received response packet that has already
/// parsed, so it is at least `FRAME_OVERHEAD` long.
fn received_value<'a>(response_bytes: &'a [u8], path: &[Tag]) -> Result<&'a [u8], ValidationError> {
    let msg = &response_bytes[FRAME_OVERHEAD..];
    let range = find_value_range(msg, path)?;
    Ok(&msg[range])
}

fn check_version(request: &Request, response: &Response) -> Result<(), ValidationError> {
    let version = *response.srep().ver();
    if request.ver().versions().contains(&version) {
        Ok(())
    } else {
        Err(ValidationError::UnofferedVersion(version))
    }
}

/// RFC 5.2.5 obliges the server, not the client; the client enforces it on its own queries
/// only. Not part of [`ResponseValidator::validate`], so stored reports that contain such a
/// response still validate.
pub fn check_vers_contains_ver(response: &Response) -> Result<(), ValidationError> {
    let ver = *response.srep().ver();
    let vers = response.srep().vers().versions();

    if vers.contains(&ver) {
        Ok(())
    } else {
        Err(ValidationError::VerNotInVers {
            ver,
            vers: vers.to_vec(),
        })
    }
}

fn check_dele_signature(
    pub_key: &PublicKey,
    response_bytes: &[u8],
    response: &Response,
) -> Result<(), ValidationError> {
    let dele_bytes = received_value(response_bytes, &[Tag::CERT, Tag::DELE])?;
    let prefix = response.srep().ver().dele_prefix();
    let signature = response.cert().sig();

    if verify_with_context(pub_key.as_ref(), prefix, dele_bytes, signature.as_ref()) {
        Ok(())
    } else {
        Err(ValidationError::BadSignature(
            "signature on DELE is invalid".to_string(),
        ))
    }
}

fn check_srep_signature(response_bytes: &[u8], response: &Response) -> Result<(), ValidationError> {
    let srep_bytes = received_value(response_bytes, &[Tag::SREP])?;
    let prefix = response.srep().ver().srep_prefix();
    let pubk = response.cert().dele().pubk();

    if verify_with_context(pubk.as_ref(), prefix, srep_bytes, response.sig().as_ref()) {
        Ok(())
    } else {
        let msg = format!(
            "signature {:?} by {:?} on SREP is invalid",
            response.sig(),
            pubk
        );
        Err(ValidationError::BadSignature(msg))
    }
}

fn check_merkle_proof(request_bytes: &[u8], response: &Response) -> Result<(), ValidationError> {
    let merkle_path = response.path();
    let index = response.indx() as usize;

    let Some(computed_root) = root_from_paths(index, request_bytes, merkle_path) else {
        let msg = format!(
            "INDX {index} has nonzero bits beyond the PATH length {}",
            merkle_path.depth()
        );
        return Err(ValidationError::FailedProof(msg));
    };
    let response_root = response.srep().root().as_array();

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

fn check_midpoint(response: &Response) -> Result<(), ValidationError> {
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

#[cfg(test)]
mod tests {
    use ValidationError::{BadSignature, InvalidMidpoint};
    use data_encoding::BASE64;
    use roughenough_common::crypto::verify_with_context;
    use roughenough_protocol::response::Response;
    use roughenough_protocol::tags::{ProtocolVersion, PublicKey};
    use roughenough_protocol::wire::FromFrame;

    use crate::transport::testing::signed_response;
    use crate::validation::{
        ResponseValidator, ValidationError, check_dele_signature, check_merkle_proof,
        check_midpoint, check_srep_signature, check_vers_contains_ver, received_value,
    };

    const RFC10049_REQUEST: &[u8] =
        include_bytes!("../../roughenough-protocol/testdata/rfc10049-request.104172a3");
    const RFC10049_RESPONSE: &[u8] =
        include_bytes!("../../roughenough-protocol/testdata/rfc10049-response.104172a3");
    const RFC10049_PUB_KEY: &[u8] = b"GX9rI+FshTLGq8g4+s1ep4m+DHaykgM0A5v6iz02jWE=";

    const DRAFT_REQUEST: &[u8] =
        include_bytes!("../../roughenough-protocol/testdata/rfc-request.071039e5");
    const DRAFT_RESPONSE: &[u8] =
        include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5");
    const DRAFT_PUB_KEY: &[u8] = b"AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=";

    fn pub_key(pub_key_b64: &[u8]) -> PublicKey {
        let pub_key = BASE64.decode(pub_key_b64).unwrap();
        PublicKey::try_from(pub_key.as_slice()).unwrap()
    }

    fn validator_for(pub_key_b64: &[u8]) -> ResponseValidator {
        ResponseValidator::new(Some(pub_key(pub_key_b64)))
    }

    fn test_request_bytes() -> Vec<u8> {
        use roughenough_protocol::ToFrame;
        use roughenough_protocol::request::Request;
        use roughenough_protocol::tags::Nonce;

        Request::new(&Nonce::from([0x42u8; 32]))
            .as_frame_bytes()
            .unwrap()
    }

    #[test]
    fn version_one_fixture_validates() {
        let response = validator_for(RFC10049_PUB_KEY)
            .validate(RFC10049_REQUEST, RFC10049_RESPONSE)
            .unwrap();
        assert_eq!(*response.srep().ver(), ProtocolVersion::RFC);
        assert_eq!(response.srep().midp(), 1_791_158_400);
    }

    #[test]
    fn draft_fixture_validates() {
        let response = validator_for(DRAFT_PUB_KEY)
            .validate(DRAFT_REQUEST, DRAFT_RESPONSE)
            .unwrap();
        assert_eq!(*response.srep().ver(), ProtocolVersion::DRAFT);
    }

    #[test]
    fn validate_returns_the_parsed_response() {
        let validated = validator_for(RFC10049_PUB_KEY)
            .validate(RFC10049_REQUEST, RFC10049_RESPONSE)
            .unwrap();
        let parsed = Response::from_frame_bytes(RFC10049_RESPONSE).unwrap();

        assert_eq!(validated.srep().midp(), parsed.srep().midp());
        assert_eq!(validated.srep().root(), parsed.srep().root());
    }

    #[test]
    fn truncated_response_is_invalid_message() {
        match validator_for(RFC10049_PUB_KEY).validate(RFC10049_REQUEST, &RFC10049_RESPONSE[..100])
        {
            Err(ValidationError::InvalidMessage(_)) => {}
            other => panic!("expected InvalidMessage, got {other:?}"),
        }
    }

    #[test]
    fn signatures_verify_only_with_their_version_context_strings() {
        use roughenough_protocol::tag::Tag;

        for (response_bytes, pub_key_b64, own, other) in [
            (
                RFC10049_RESPONSE,
                RFC10049_PUB_KEY,
                ProtocolVersion::RFC,
                ProtocolVersion::DRAFT,
            ),
            (
                DRAFT_RESPONSE,
                DRAFT_PUB_KEY,
                ProtocolVersion::DRAFT,
                ProtocolVersion::RFC,
            ),
        ] {
            let response = Response::from_frame_bytes(response_bytes).unwrap();
            let long_term_key = BASE64.decode(pub_key_b64).unwrap();
            let dele = received_value(response_bytes, &[Tag::CERT, Tag::DELE]).unwrap();
            let srep = received_value(response_bytes, &[Tag::SREP]).unwrap();
            let dele_sig = response.cert().sig().as_ref();
            let srep_sig = response.sig().as_ref();
            let online_key = response.cert().dele().pubk().as_ref();

            assert!(verify_with_context(
                &long_term_key,
                own.dele_prefix(),
                dele,
                dele_sig
            ));
            assert!(!verify_with_context(
                &long_term_key,
                other.dele_prefix(),
                dele,
                dele_sig
            ));
            assert!(verify_with_context(
                online_key,
                own.srep_prefix(),
                srep,
                srep_sig
            ));
            assert!(!verify_with_context(
                online_key,
                other.srep_prefix(),
                srep,
                srep_sig
            ));
        }
    }

    #[test]
    fn response_with_unoffered_version_is_rejected() {
        use roughenough_protocol::ToFrame;
        use roughenough_protocol::request::Request;

        // RFC 7: "version numbers not in the request" make a response invalid
        let response = Response::from_frame_bytes(RFC10049_RESPONSE).unwrap();
        let request = Request::new_with_versions(response.nonc(), &[ProtocolVersion::DRAFT]);
        let request_bytes = request.as_frame_bytes().unwrap();

        match validator_for(RFC10049_PUB_KEY).validate(&request_bytes, RFC10049_RESPONSE) {
            Err(ValidationError::UnofferedVersion(v)) => assert_eq!(v, ProtocolVersion::RFC),
            other => panic!("expected UnofferedVersion, got {other:?}"),
        }

        // A draft response to a client that offered only version 1
        let response = Response::from_frame_bytes(DRAFT_RESPONSE).unwrap();
        let request = Request::new(response.nonc());
        let request_bytes = request.as_frame_bytes().unwrap();

        match validator_for(DRAFT_PUB_KEY).validate(&request_bytes, DRAFT_RESPONSE) {
            Err(ValidationError::UnofferedVersion(v)) => assert_eq!(v, ProtocolVersion::DRAFT),
            other => panic!("expected UnofferedVersion, got {other:?}"),
        }
    }

    #[test]
    fn dele_signature_is_validated() {
        let response = Response::from_frame_bytes(DRAFT_RESPONSE).unwrap();
        let long_term_key = pub_key(DRAFT_PUB_KEY);

        check_dele_signature(&long_term_key, DRAFT_RESPONSE, &response).unwrap();
    }

    #[test]
    fn srep_signature_is_validated() {
        use roughenough_protocol::ToFrame;
        use roughenough_server::test_utils::TestContext;

        let mut ctx = TestContext::new(64);
        let (_request, response) = ctx.create_interaction_pair(1000);
        let response_bytes = response.as_frame_bytes().unwrap();

        check_srep_signature(&response_bytes, &response).unwrap();
    }

    #[test]
    fn corrupt_dele_signature_is_detected() {
        use roughenough_protocol::header::find_value_range;
        use roughenough_protocol::tag::Tag;
        use roughenough_protocol::wire::FRAME_OVERHEAD;

        let mut response_bytes = DRAFT_RESPONSE.to_vec();

        // Corrupt the last byte of the DELE value (high byte of MAXT) in the
        // received bytes; the message still parses but the signature is broken
        let dele_range =
            find_value_range(&response_bytes[FRAME_OVERHEAD..], &[Tag::CERT, Tag::DELE]).unwrap();
        response_bytes[FRAME_OVERHEAD + dele_range.end - 1] ^= 0xff;

        let response = Response::from_frame_bytes(&response_bytes).unwrap();
        let long_term_key = pub_key(DRAFT_PUB_KEY);

        match check_dele_signature(&long_term_key, &response_bytes, &response) {
            Err(BadSignature(msg)) => assert!(msg.contains("DELE")), // ok, expected failure
            Err(e) => panic!("expected BadSignature, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn corrupt_srep_signature_is_detected() {
        use roughenough_protocol::ToFrame;
        use roughenough_protocol::header::find_value_range;
        use roughenough_protocol::tag::Tag;
        use roughenough_protocol::wire::FRAME_OVERHEAD;
        use roughenough_server::test_utils::TestContext;

        let mut ctx = TestContext::new(64);
        let (_request, response) = ctx.create_interaction_pair(1000);
        let mut response_bytes = response.as_frame_bytes().unwrap();

        // Corrupt the last byte of the SREP value (part of ROOT) in the received bytes
        let srep_range = find_value_range(&response_bytes[FRAME_OVERHEAD..], &[Tag::SREP]).unwrap();
        response_bytes[FRAME_OVERHEAD + srep_range.end - 1] ^= 0xff;

        match check_srep_signature(&response_bytes, &response) {
            Err(BadSignature(msg)) => assert!(msg.contains("SREP")), // ok, expected failure
            Err(e) => panic!("expected BadSignature, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn midpoint_is_validated() {
        let response1 = Response::from_frame_bytes(DRAFT_RESPONSE).unwrap();

        // Happy-path should pass
        check_midpoint(&response1).unwrap();
    }

    #[test]
    fn midpoint_outside_of_dele_bounds_is_detected() {
        let response = Response::from_frame_bytes(DRAFT_RESPONSE).unwrap();

        //
        // Change request so that the midpoint is *before* MINT
        //
        let mut response1 = response.clone();
        let mut cert1 = response1.cert().clone();
        let mut dele1 = cert1.dele().clone();

        dele1.set_mint(response1.srep().midp() + 1000);
        cert1.set_dele(dele1);
        response1.set_cert(cert1);

        match check_midpoint(&response1) {
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

        match check_midpoint(&response2) {
            Err(InvalidMidpoint(msg)) => assert!(msg.contains("after")),
            Err(e) => panic!("expected InvalidMidpoint, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn merkle_proof_with_wrong_nonce_is_detected() {
        use roughenough_protocol::ToWire;
        use roughenough_protocol::request::RequestPlain;
        use roughenough_protocol::tags::Nonce;

        let nonce = Nonce::from([0x42u8; 32]);
        let request = RequestPlain::new(&nonce);
        let request_bytes = request.as_bytes().unwrap();

        let response = Response::from_frame_bytes(DRAFT_RESPONSE).unwrap();

        // This should fail because the response was for a different nonce
        match check_merkle_proof(&request_bytes, &response) {
            Err(ValidationError::FailedProof(_)) => {} // ok, expected failure
            Err(e) => panic!("expected ValidationError::FailedProof, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn greased_response_with_valid_signatures_validates() {
        // RFC 7 / 9.2: a response may carry undefined tags (including inside
        // SREP and DELE) with signatures computed over the bytes as sent. The
        // client MUST ignore the undefined tags and the response validates.
        let request_bytes = test_request_bytes();
        let (pub_key, response_bytes) = signed_response(
            &request_bytes,
            ProtocolVersion::RFC,
            &[ProtocolVersion::RFC],
            true,
        );
        let validator = ResponseValidator::new(Some(pub_key));

        let response = validator.validate(&request_bytes, &response_bytes).unwrap();
        assert_eq!(response.srep().midp(), 1000);
    }

    #[test]
    fn vers_without_ver_is_rejected() {
        let request_bytes = test_request_bytes();
        let (pub_key, response_bytes) = signed_response(
            &request_bytes,
            ProtocolVersion::RFC,
            &[ProtocolVersion::DRAFT],
            false,
        );

        // The reporting path validates with `validate` alone, so it still accepts the response
        let validator = ResponseValidator::new(Some(pub_key));
        let response = validator.validate(&request_bytes, &response_bytes).unwrap();

        match check_vers_contains_ver(&response) {
            Err(ValidationError::VerNotInVers { ver, vers }) => {
                assert_eq!(ver, ProtocolVersion::RFC);
                assert_eq!(vers, vec![ProtocolVersion::DRAFT]);
            }
            other => panic!("expected VerNotInVers, got {other:?}"),
        }
    }

    #[test]
    fn vers_with_ver_passes() {
        let request_bytes = test_request_bytes();
        let (_, response_bytes) = signed_response(
            &request_bytes,
            ProtocolVersion::RFC,
            &[ProtocolVersion::RFC, ProtocolVersion::DRAFT],
            false,
        );
        let response = Response::from_frame_bytes(&response_bytes).unwrap();

        check_vers_contains_ver(&response).unwrap();
    }

    #[test]
    fn merkle_proof_with_leftover_index_bits_is_detected() {
        use roughenough_protocol::ToFrame;
        use roughenough_server::test_utils::TestContext;

        let mut ctx = TestContext::new(64);
        let (request, mut response) = ctx.create_interaction_pair(1000);
        let request_bytes = request.as_frame_bytes().unwrap();

        // Sanity check: the unmodified proof is valid
        check_merkle_proof(&request_bytes, &response).unwrap();

        // RFC 5.3.1: any nonzero INDX bits beyond the PATH length must fail
        response.set_indx(response.indx() | (1 << response.path().depth()));

        match check_merkle_proof(&request_bytes, &response) {
            Err(ValidationError::FailedProof(_)) => {} // ok, expected failure
            Err(e) => panic!("expected ValidationError::FailedProof, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }
}

#[cfg(test)]
mod causality {
    use super::*;
    use crate::test_utils::{hostile_measurement, measurement};

    #[test]
    fn midpoint_smaller_than_radius_saturates_and_is_not_a_violation() {
        // MIDP < RADI must saturate to zero
        let hostile = hostile_measurement(10, 100);
        assert_eq!(hostile.lower_bound(), 0);

        let normal = measurement(1000);
        let violations = CausalityViolation::find(&[hostile, normal]);
        assert!(
            violations.is_empty(),
            "saturated lower bound must not flag a violation against an honest server"
        );
    }

    #[test]
    fn midpoint_near_u64_max_saturates() {
        let hostile = hostile_measurement(u64::MAX - 1, 100);
        assert_eq!(hostile.upper_bound(), u64::MAX);
    }

    #[test]
    fn empty() {
        let measurements = vec![];
        let result = CausalityViolation::find(&measurements);
        assert!(
            result.is_empty(),
            "Empty measurements should return no violations"
        );
    }

    #[test]
    fn single() {
        let measurements = vec![measurement(1000000)];
        let result = CausalityViolation::find(&measurements);
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
        let measurements = vec![measurement(1000), measurement(2000), measurement(3000)];

        let result = CausalityViolation::find(&measurements);
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
        let measurements = vec![measurement(2000), measurement(1000)];

        let violations = CausalityViolation::find(&measurements);
        assert!(
            !violations.is_empty(),
            "Invalid sequence should return some violations"
        );

        assert_eq!(violations.len(), 1, "Should have exactly one violation");

        let v = &violations[0];
        assert_eq!(v.lower_bound_i(), 1995);
        assert_eq!(v.upper_bound_j(), 1005);
        assert_eq!((v.index_i(), v.index_j()), (0, 1));
        assert_eq!(v.chain().len(), 2, "chain covers measurements 0..=j");
    }

    #[test]
    fn multiple_violations() {
        // Create multiple violations
        // M0: [2995, 3005]
        // M1: [ 995, 1005] - violates with M0
        // M2: [1000, 1010] - violates with M0
        let measurements = vec![measurement(3000), measurement(1000), measurement(1005)];

        let violations = CausalityViolation::find(&measurements);
        assert!(!violations.is_empty(), "Should have violations");
        assert_eq!(violations.len(), 2, "Should have exactly two violations");

        // Check first violation (0,1)
        assert_eq!(violations[0].lower_bound_i(), 2995);
        assert_eq!(violations[0].upper_bound_j(), 1005);
        assert_eq!(violations[0].chain().len(), 2);

        // Check second violation (0,2)
        assert_eq!(violations[1].lower_bound_i(), 2995);
        assert_eq!(violations[1].upper_bound_j(), 1010);
        assert_eq!(violations[1].chain().len(), 3);
    }

    #[test]
    fn edge_case() {
        // boundary condition: lower_bound_i == upper_bound_j
        // M0: [995, 1005]
        // M1: [985, 995]
        // This is valid (995 <= 995)
        let measurements = vec![measurement(1000), measurement(990)];

        let result = CausalityViolation::find(&measurements);
        assert!(result.is_empty(), "Exact boundary should be valid");
    }

    #[test]
    fn violating_pairs_boundary_is_not_a_violation() {
        // lower_i == upper_j is causally consistent; only strictly greater
        // demonstrates a violation
        assert!(violating_pairs(&[interval(1000, 5), interval(990, 5)]).is_empty());
        assert_eq!(
            violating_pairs(&[interval(1001, 5), interval(990, 5)]),
            vec![(0, 1)]
        );
    }

    #[test]
    fn violating_pairs_hostile_bounds_saturate() {
        // MIDP < RADI saturates to zero instead of wrapping
        assert!(violating_pairs(&[interval(10, 100), interval(1000, 5)]).is_empty());
        // MIDP near u64::MAX saturates the upper bound
        assert!(violating_pairs(&[interval(u64::MAX, 5), interval(u64::MAX - 1, 100)]).is_empty());
    }
}
