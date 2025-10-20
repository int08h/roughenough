use client::{MalfeasanceReport, ReportEntry, ResponseValidator};
use common::crypto::calculate_chained_nonce;
use data_encoding::BASE64;
use protocol::cursor::ParseCursor;
use protocol::request::Request;
use protocol::response::Response;
use protocol::tags::PublicKey;
use protocol::wire::FromFrame;

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

/// Validate a single request/response pair
fn validate_entry(
    request_bytes: &[u8],
    response: &Response,
    public_key_bytes: &[u8],
    index: usize,
) -> Result<(), String> {
    let public_key = PublicKey::from(public_key_bytes);
    let validator = ResponseValidator::new_with_key(public_key);

    validator
        .validate(request_bytes, response)
        .map(|_| ()) // Discard the midpoint value
        .map_err(|e| format!("Entry {index}: validation failed: {e}"))
}

/// Validate chaining between consecutive entries
fn validate_chaining(
    request: &Request,
    decoded: &DecodedEntry,
    previous_response: Option<&Response>,
    index: usize,
) -> Result<(), String> {
    match previous_response {
        None => {
            // First entry should not have rand value
            if decoded.rand_bytes.is_some() {
                return Err(format!(
                    "Entry {index}: first entry has a rand value, but it shouldn't"
                ));
            }
        }
        Some(prev_response) => {
            // Second and later entries must have rand value
            let rand_bytes = decoded
                .rand_bytes
                .as_ref()
                .ok_or(format!("Entry {index}: missing a rand value"))?;

            let expected_nonce = calculate_chained_nonce(prev_response, rand_bytes);
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

/// Validate a malfeasance report containing multiple request/response pairs
pub fn validate_report(report: &MalfeasanceReport) -> Result<(), String> {
    if report.responses().len() < 2 {
        return Err("Need at least 2 entries for causality violation".into());
    }

    let mut previous_response: Option<Response> = None;

    for (i, entry) in report.responses().iter().enumerate() {
        // Decode all base64 fields
        let decoded = decode_entry_base64(entry, i)?;

        // Parse request and response
        let (request, response) = parse_interaction_pair(&decoded, i)?;

        // Validate the request/response pair
        validate_entry(
            &decoded.request_bytes,
            &response,
            &decoded.public_key_bytes,
            i,
        )?;

        // Validate chaining
        validate_chaining(&request, &decoded, previous_response.as_ref(), i)?;

        // Store response for next iteration
        previous_response = Some(response);
    }

    Ok(())
}
