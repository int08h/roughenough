//! Failure-path coverage for Response parsing, mirroring the adversarial
//! request suite: start from a valid serialized response and mutate it.
//! Every case must produce a clean `Err`, never a panic.

use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::error::Error;
use roughenough_protocol::response::Response;
use roughenough_protocol::util::test_utils::{
    build_msg, frame, parse_entries, replace_value, value_range,
};
use roughenough_protocol::wire::FromFrame;

/// A valid framed response with an 8-element PATH (INDX 2)
const VALID_RESPONSE: &[u8] = include_bytes!("../testdata/rfc-response.path8.index2.4c16c619");

/// The raw message bytes (framing stripped) of the valid response
fn valid_msg() -> Vec<u8> {
    VALID_RESPONSE[12..].to_vec()
}

fn parse_framed(mut framed: Vec<u8>) -> Result<Response, Error> {
    let mut cursor = ParseCursor::new(&mut framed);
    Response::from_frame(&mut cursor)
}

#[test]
fn baseline_response_parses() {
    let response = parse_framed(VALID_RESPONSE.to_vec()).unwrap();
    assert_eq!(response.indx(), 2);
}

#[test]
fn missing_mandatory_tag_is_rejected() {
    // RFC 5.2: a response MUST contain SIG, NONC, TYPE, PATH, SREP, CERT,
    // and INDX; dropping any one of them must fail
    for tag in [
        b"SIG\x00", b"NONC", b"TYPE", b"PATH", b"SREP", b"CERT", b"INDX",
    ] {
        let msg = valid_msg();
        let entries: Vec<([u8; 4], Vec<u8>)> = parse_entries(&msg)
            .into_iter()
            .filter(|(t, _)| t != tag)
            .collect();
        let framed = frame(&build_msg(&entries));

        let result = parse_framed(framed);
        assert!(
            result.is_err(),
            "response without {} must be rejected",
            String::from_utf8_lossy(tag)
        );
    }
}

#[test]
fn missing_ver_inside_srep_is_rejected() {
    let msg = valid_msg();
    let srep_range = value_range(&msg, *b"SREP");
    let srep_entries: Vec<([u8; 4], Vec<u8>)> = parse_entries(&msg[srep_range])
        .into_iter()
        .filter(|(t, _)| t != b"VER\x00")
        .collect();
    let new_srep = build_msg(&srep_entries);
    let framed = frame(&replace_value(&msg, *b"SREP", &new_srep));

    let result = parse_framed(framed);
    assert!(
        matches!(result, Err(Error::MissingTag("VER"))),
        "{result:?}"
    );
}

#[test]
fn out_of_order_tags_are_rejected() {
    // RFC 4.2: tags are placed in increasing (little-endian) order; swap the
    // first two entries wholesale (tags and values move together)
    let msg = valid_msg();
    let mut entries = parse_entries(&msg);
    entries.swap(0, 1);
    let framed = frame(&build_msg(&entries));

    let result = parse_framed(framed);
    assert!(
        matches!(result, Err(Error::UnorderedTag(_, _))),
        "{result:?}"
    );
}

#[test]
fn duplicate_tags_are_rejected() {
    // RFC 4.2: a tag MUST NOT appear more than once; strict ordering also
    // forbids equality, so a duplicated NONC entry must fail
    let msg = valid_msg();
    let mut entries = parse_entries(&msg);
    let nonc = entries.iter().find(|(t, _)| t == b"NONC").cloned().unwrap();
    let pos = entries.iter().position(|(t, _)| t == b"NONC").unwrap();
    entries.insert(pos, nonc);
    let framed = frame(&build_msg(&entries));

    let result = parse_framed(framed);
    assert!(
        matches!(result, Err(Error::UnorderedTag(_, _))),
        "{result:?}"
    );
}

#[test]
fn truncated_values_are_rejected() {
    // Shrinking a nested message must fail cleanly no matter how much is
    // cut: off by 1 (breaks 4-byte alignment), off by 4 (aligned but short),
    // and half the value
    for tag in [*b"SREP", *b"CERT"] {
        let msg = valid_msg();
        let full = msg[value_range(&msg, tag)].to_vec();

        for cut in [1usize, 4, full.len() / 2] {
            let truncated = &full[..full.len() - cut];
            let framed = frame(&replace_value(&msg, tag, truncated));

            let result = parse_framed(framed);
            assert!(
                result.is_err(),
                "{} truncated by {cut} bytes must be rejected",
                String::from_utf8_lossy(&tag)
            );
        }
    }
}

#[test]
fn truncated_path_is_rejected() {
    // Half of the 8-element PATH (128 bytes) is itself a structurally valid
    // 4-element PATH, so only the non-multiple-of-32 truncations must fail
    let msg = valid_msg();
    let full = msg[value_range(&msg, *b"PATH")].to_vec();

    for cut in [1usize, 4] {
        let truncated = &full[..full.len() - cut];
        let framed = frame(&replace_value(&msg, *b"PATH", truncated));

        let result = parse_framed(framed);
        assert!(
            result.is_err(),
            "PATH truncated by {cut} bytes must be rejected"
        );
    }
}

#[test]
fn truncated_dele_inside_cert_is_rejected() {
    let msg = valid_msg();
    let cert_range = value_range(&msg, *b"CERT");
    let cert = msg[cert_range].to_vec();
    let dele = cert[value_range(&cert, *b"DELE")].to_vec();

    for cut in [1usize, 4, dele.len() / 2] {
        let new_cert = replace_value(&cert, *b"DELE", &dele[..dele.len() - cut]);
        let framed = frame(&replace_value(&msg, *b"CERT", &new_cert));

        let result = parse_framed(framed);
        assert!(
            result.is_err(),
            "DELE truncated by {cut} bytes must be rejected"
        );
    }
}

#[test]
fn path_not_multiple_of_32_is_rejected() {
    // RFC 5.2.4: PATH is a multiple of 32 bytes
    for len in [1usize, 31, 33, 255, 260] {
        let msg = valid_msg();
        let framed = frame(&replace_value(&msg, *b"PATH", &vec![0x11u8; len]));

        let result = parse_framed(framed);
        assert!(result.is_err(), "PATH of {len} bytes must be rejected");
    }
}

#[test]
fn path_over_32_elements_is_rejected() {
    // 33 elements exceeds the 32-element maximum implied by the 32-bit INDX
    let msg = valid_msg();
    let framed = frame(&replace_value(&msg, *b"PATH", &[0x22u8; 33 * 32]));

    let result = parse_framed(framed);
    assert!(result.is_err(), "PATH of 33 elements must be rejected");
}

#[test]
fn path_of_exactly_32_elements_parses() {
    // Companion positive case: the RFC maximum itself is accepted
    let msg = valid_msg();
    let framed = frame(&replace_value(&msg, *b"PATH", &[0x33u8; 32 * 32]));

    let response = parse_framed(framed).unwrap();
    assert_eq!(response.path().as_ref().len(), 32 * 32);
}

#[test]
fn wrong_message_type_is_rejected() {
    // RFC 5.2.3: responses with a TYPE other than 1 MUST be ignored
    for bad_type in [0u32, 2, 0xffff_ffff] {
        let msg = valid_msg();
        let framed = frame(&replace_value(&msg, *b"TYPE", &bad_type.to_le_bytes()));

        let result = parse_framed(framed);
        assert!(
            matches!(result, Err(Error::InvalidMessageType(t)) if t == bad_type),
            "TYPE {bad_type:#x} must be rejected: {result:?}"
        );
    }
}

#[test]
fn declared_frame_length_longer_than_buffer_is_rejected() {
    let mut framed = VALID_RESPONSE.to_vec();
    let msg_len = (framed.len() - 12) as u32;
    framed[8..12].copy_from_slice(&(msg_len + 4).to_le_bytes());

    let result = parse_framed(framed);
    assert!(
        matches!(result, Err(Error::BufferTooSmall(_, _))),
        "{result:?}"
    );
}

#[test]
fn declared_frame_length_shorter_than_message_is_rejected() {
    // A shorter declared length truncates the message mid-values; header
    // validation against the shortened length must fail
    let mut framed = VALID_RESPONSE.to_vec();
    let msg_len = (framed.len() - 12) as u32;
    framed[8..12].copy_from_slice(&(msg_len - 4).to_le_bytes());

    let result = parse_framed(framed);
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn declared_frame_length_below_minimum_is_rejected() {
    let mut framed = VALID_RESPONSE.to_vec();
    framed[8..12].copy_from_slice(&8u32.to_le_bytes());

    let result = parse_framed(framed);
    assert!(
        matches!(result, Err(Error::UnexpectedFraming(_))),
        "{result:?}"
    );
}

#[test]
fn trailing_bytes_after_frame_are_ignored() {
    // The declared frame length bounds parsing (truncate_remaining); bytes
    // after the frame must not be counted toward the last tag's value
    let mut framed = VALID_RESPONSE.to_vec();
    framed.extend_from_slice(&[0xee; 64]);

    let response = parse_framed(framed).unwrap();
    assert_eq!(response.indx(), 2);
}

#[test]
fn bad_magic_is_rejected() {
    let mut framed = VALID_RESPONSE.to_vec();
    framed[0] ^= 0xff;

    let result = parse_framed(framed);
    assert!(
        matches!(result, Err(Error::UnexpectedMagic(_))),
        "{result:?}"
    );
}

#[test]
fn wrong_indx_size_is_rejected() {
    let msg = valid_msg();
    let framed = frame(&replace_value(&msg, *b"INDX", &[0x01u8; 8]));

    let result = parse_framed(framed);
    assert!(
        matches!(result, Err(Error::WrongTagSize(4, 8))),
        "{result:?}"
    );
}

#[test]
fn wrong_nonc_size_is_rejected() {
    // 28 stays 4-byte aligned so the header parses and the NONC size check
    // itself must reject (an unaligned length fails earlier, at the offsets)
    let msg = valid_msg();
    let framed = frame(&replace_value(&msg, *b"NONC", &[0x42u8; 28]));

    let result = parse_framed(framed);
    assert!(
        matches!(result, Err(Error::WrongTagSize(32, 28))),
        "{result:?}"
    );
}
