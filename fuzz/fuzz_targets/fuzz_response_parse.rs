#![no_main]

use libfuzzer_sys::fuzz_target;
use roughenough_protocol::ToWire;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::MessageType;
use roughenough_protocol::wire::{FromFrame, FromWire};

fuzz_target!(|data: &[u8]| {
    // The client parses received datagrams with from_frame; fuzzing it on the
    // same input covers the framing layer (magic, length, truncate_remaining)
    // that from_wire alone never reaches
    let mut frame_copy = data.to_vec();
    let mut cursor = ParseCursor::new(&mut frame_copy);
    let _ = Response::from_frame(&mut cursor);

    // Try to parse a response
    let mut data_copy = data.to_vec();
    let mut cursor = ParseCursor::new(&mut data_copy);
    match Response::from_wire(&mut cursor) {
        Ok(response) => {
            // Parsing reconstructs a canonical form that drops unknown tags
            // and unknown VERS entries, so wire_size may legitimately shrink
            // below MINIMUM_SIZE; the invariants are the message type and
            // that the canonical form round-trips. One known asymmetry is
            // excluded: a VERS holding only unknown versions parses to an
            // empty list, which cannot be reserialized (NoSupportedVersions).
            assert_eq!(response.msg_type(), MessageType::Response);
            if !response.srep().vers().versions().is_empty() {
                let mut bytes = response.as_bytes().expect("reserialization failed");
                let mut cursor = ParseCursor::new(&mut bytes);
                let reparsed = Response::from_wire(&mut cursor).expect("reparse failed");
                assert_eq!(reparsed, response);
            }
        }
        Err(_) => {
            // Error is expected for most fuzz inputs
        }
    }
});
