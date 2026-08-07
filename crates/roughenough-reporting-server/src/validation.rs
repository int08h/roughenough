use data_encoding::BASE64;
use roughenough_client::{MalfeasanceReport, ReportEntry, ResponseValidator};
use roughenough_common::crypto::calculate_chained_nonce;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::PublicKey;
use roughenough_protocol::wire::FromFrame;

/// Convenience struct to decode base64 data from a ReportEntry
struct DecodedEntry {
    request_bytes: Vec<u8>,
    response_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    rand_bytes: Option<Vec<u8>>,
}

/// Decode all base64 fields of a `ReportEntry`
fn decode_entry_base64(entry: &ReportEntry, index: usize) -> Result<DecodedEntry, String> {
    let request_bytes = BASE64
        .decode(entry.request().as_bytes())
        .map_err(|e| format!("Entry {index}: invalid request: {e}"))?;

    let response_bytes = BASE64
        .decode(entry.response().as_bytes())
        .map_err(|e| format!("Entry {index}: invalid response: {e}"))?;

    let public_key_bytes = BASE64
        .decode(entry.public_key().as_bytes())
        .map_err(|e| format!("Entry {index}: invalid public key: {e}"))?;

    // Validate public key length
    if public_key_bytes.len() != 32 {
        return Err(format!(
            "Entry {index}: public key must be 32 bytes, got {}",
            public_key_bytes.len()
        ));
    }

    // Decode rand if present
    let rand_bytes = match entry.rand() {
        None => None,
        Some(rand_str) => {
            let bytes = BASE64
                .decode(rand_str.as_bytes())
                .map_err(|e| format!("Entry {index}: invalid rand: {e}"))?;

            if bytes.len() != 32 {
                return Err(format!(
                    "Entry {index}: rand must be 32 bytes, got {}",
                    bytes.len()
                ));
            }
            Some(bytes)
        }
    };

    Ok(DecodedEntry {
        request_bytes,
        response_bytes,
        public_key_bytes,
        rand_bytes,
    })
}

/// Parse request and response from their wire format
fn parse_interaction_pair(
    decoded: &DecodedEntry,
    index: usize,
) -> Result<(Request, Response), String> {
    // Parse request
    let mut request_bytes_mut = decoded.request_bytes.clone();
    let mut request_cursor = ParseCursor::new(&mut request_bytes_mut);
    let request = Request::from_frame(&mut request_cursor)
        .map_err(|e| format!("Entry {index}: invalid request: {e}"))?;

    // Parse response
    let mut response_bytes_mut = decoded.response_bytes.clone();
    let mut response_cursor = ParseCursor::new(&mut response_bytes_mut);
    let response = Response::from_frame(&mut response_cursor)
        .map_err(|e| format!("Entry {index}: invalid response: {e}"))?;

    Ok((request, response))
}

/// Validate a single request/response pair. `response_bytes` is the response
/// packet exactly as reported; signatures are verified over those bytes.
fn validate_entry(
    request_bytes: &[u8],
    response_bytes: &[u8],
    response: &Response,
    public_key_bytes: &[u8],
    index: usize,
) -> Result<(), String> {
    let public_key = PublicKey::from(public_key_bytes);
    let validator = ResponseValidator::new_with_key(public_key);

    validator
        .validate(request_bytes, response_bytes, response)
        .map(|_| ()) // Discard the midpoint value
        .map_err(|e| format!("Entry {index}: validation failed: {e}"))
}

/// Validate chaining between consecutive entries. `previous_response` is the
/// prior entry's response packet exactly as reported.
fn validate_chaining(
    request: &Request,
    decoded: &DecodedEntry,
    previous_response: Option<&[u8]>,
    index: usize,
) -> Result<(), String> {
    match previous_response {
        // RFC 8.4.1: the first nonce is unchained, so rand "MAY be omitted"
        // from the first entry; when present it carries no meaning and is
        // accepted and ignored
        None => {}
        Some(prev_response_frame) => {
            // Second and later entries must have rand value
            let rand_bytes = decoded
                .rand_bytes
                .as_ref()
                .ok_or(format!("Entry {index}: missing a rand value"))?;

            let expected_nonce = calculate_chained_nonce(prev_response_frame, rand_bytes);
            let found_nonce = *request.nonc();

            if found_nonce != expected_nonce {
                return Err(format!(
                    "Entry {index}: found nonce {found_nonce:?} doesn't match expected nonce {expected_nonce:?}",
                ));
            }
        }
    }

    Ok(())
}

/// True when some pair (i < j) demonstrates a causality violation:
/// `MIDP_i - RADI_i > MIDP_j + RADI_j`. The saturating arithmetic mirrors the
/// client's `Measurement::lower_bound`/`upper_bound` on these wire-derived
/// values, so client and server agree on what constitutes a violation.
fn demonstrates_violation(bounds: &[(u64, u32)]) -> bool {
    bounds.iter().enumerate().any(|(i, &(midp_i, radi_i))| {
        bounds[i + 1..].iter().any(|&(midp_j, radi_j)| {
            midp_i.saturating_sub(radi_i as u64) > midp_j.saturating_add(radi_j as u64)
        })
    })
}

/// Validate a malfeasance report containing multiple request/response pairs
pub fn validate_report(report: &MalfeasanceReport) -> Result<(), String> {
    if report.responses().len() < 2 {
        return Err("Need at least 2 entries for causality violation".into());
    }

    let mut previous_response: Option<Vec<u8>> = None;
    let mut bounds: Vec<(u64, u32)> = Vec::with_capacity(report.responses().len());

    for (i, entry) in report.responses().iter().enumerate() {
        // Decode all base64 fields
        let decoded = decode_entry_base64(entry, i)?;

        // Parse request and response
        let (request, response) = parse_interaction_pair(&decoded, i)?;

        // Validate the request/response pair
        validate_entry(
            &decoded.request_bytes,
            &decoded.response_bytes,
            &response,
            &decoded.public_key_bytes,
            i,
        )?;

        // Validate chaining
        validate_chaining(&request, &decoded, previous_response.as_deref(), i)?;

        bounds.push((response.srep().midp(), response.srep().radi()));

        // The chained nonce covers the response packet exactly as received
        previous_response = Some(decoded.response_bytes.clone());
    }

    // A valid chain only proves the responses arrived in order; the report
    // must also prove the claim itself, or any two honest measurements would
    // be stored as "malfeasance"
    if !demonstrates_violation(&bounds) {
        return Err("no causality violation demonstrated".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use roughenough_client::CausalityViolation;
    use roughenough_client::measurement::Measurement;
    use roughenough_common::crypto::{calculate_chained_nonce, random_bytes};
    use roughenough_protocol::ToFrame;
    use roughenough_protocol::tags::Nonce;
    use roughenough_server::test_utils::TestContext;

    use super::*;

    /// Build a properly chained measurement sequence: measurement 0 uses a
    /// random nonce; each later measurement's nonce is
    /// H(prior_response || rand). `first_rand` optionally attaches a
    /// (meaningless) rand to the first measurement.
    fn create_chained_measurements(
        midpoints: &[u64],
        first_rand: Option<[u8; 32]>,
    ) -> Vec<Measurement> {
        let mut prior_response: Option<Vec<u8>> = None;
        let mut measurements = Vec::new();

        for &midpoint in midpoints {
            // one context per exchange; all contexts share a seed, so the
            // measurements present one server identity
            let mut ctx = TestContext::new(1);

            let (nonce, rand_value) = match prior_response.as_deref() {
                Some(prior) => {
                    let rand = random_bytes::<32>();
                    (calculate_chained_nonce(prior, &rand), Some(rand))
                }
                None => (Nonce::from(random_bytes::<32>()), first_rand),
            };

            let (request, response) = ctx.create_interaction_pair_with_nonce(midpoint, &nonce);
            let response_bytes = response.as_frame_bytes().unwrap();

            let measurement = Measurement::builder()
                .server("127.0.0.1:2003".parse().unwrap())
                .hostname("test".to_string())
                .public_key(Some(ctx.key_source.public_key()))
                .request(request)
                .response(response)
                .response_bytes(response_bytes.clone())
                .rand_value(rand_value)
                .build()
                .unwrap();

            prior_response = Some(response_bytes);
            measurements.push(measurement);
        }

        measurements
    }

    fn create_chained_report(midpoints: &[u64], first_rand: Option<[u8; 32]>) -> MalfeasanceReport {
        let measurements = create_chained_measurements(midpoints, first_rand);
        let violation = CausalityViolation::new(&measurements, 0, measurements.len() - 1);
        MalfeasanceReport::from_violation(&violation)
    }

    #[test]
    fn chained_report_without_violation_is_rejected() {
        let base = TestContext::new(1).clock.epoch_seconds();

        // Correctly chained, causally consistent times: signatures and nonce
        // chain check out, but no malfeasance is demonstrated
        let report = create_chained_report(&[base, base + 1_000, base + 2_000], None);

        let err = validate_report(&report).unwrap_err();
        assert!(
            err.contains("no causality violation demonstrated"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn chained_report_with_violation_is_accepted() {
        let base = TestContext::new(1).clock.epoch_seconds();

        let report = create_chained_report(&[base + 2_000_000, base + 1_000_000, base], None);

        validate_report(&report).expect("violating chained report must validate");
    }

    #[test]
    fn first_entry_carrying_rand_is_accepted() {
        let base = TestContext::new(1).clock.epoch_seconds();

        // RFC 8.4.1: rand MAY be omitted from the first entry; carrying one
        // is not an error
        let report = create_chained_report(&[base + 2_000_000, base], Some([0x77u8; 32]));
        assert!(report.responses()[0].rand().is_some());

        validate_report(&report).expect("first-entry rand must be accepted and ignored");
    }

    #[test]
    fn boundary_is_not_a_violation() {
        // lower_i == upper_j is causally consistent; only strictly greater
        // demonstrates a violation, matching the client's comparison
        assert!(!demonstrates_violation(&[(1000, 5), (990, 5)]));
        assert!(demonstrates_violation(&[(1001, 5), (990, 5)]));
    }

    #[test]
    fn hostile_bounds_saturate() {
        // MIDP < RADI saturates to zero instead of wrapping; wrapped bounds
        // would fabricate a violation out of honest measurements
        assert!(!demonstrates_violation(&[(10, 100), (1000, 5)]));
        // MIDP near u64::MAX saturates the upper bound
        assert!(!demonstrates_violation(&[
            (u64::MAX, 5),
            (u64::MAX - 1, 100)
        ]));
    }
}
