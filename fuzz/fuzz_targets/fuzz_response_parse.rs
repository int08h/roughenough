#![no_main]

use libfuzzer_sys::fuzz_target;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::MessageType;
use roughenough_protocol::ToWire;
use roughenough_protocol::wire::FromWire;

fuzz_target!(|data: &[u8]| {
    // Create a mutable copy of the data
    let mut data_copy = data.to_vec();
    
    // Try to parse a response
    let mut cursor = ParseCursor::new(&mut data_copy);
    match Response::from_wire(&mut cursor) {
        Ok(response) => {
            // these must be true for all valid responses
            assert_eq!(response.msg_type(), MessageType::Response);
            assert!(response.wire_size() > Response::MINIMUM_SIZE);
        }
        Err(_) => {
            // Error is expected for most fuzz inputs
        }
    }
});