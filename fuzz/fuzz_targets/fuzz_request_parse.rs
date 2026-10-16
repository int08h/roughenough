#![no_main]

use libfuzzer_sys::fuzz_target;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::wire::FromFrame;

// Encode/parse round trips of well-formed requests are asserted in fuzz-structured
fuzz_target!(|data: &[u8]| {
    let mut data_copy = data.to_vec();
    let mut cursor = ParseCursor::new(&mut data_copy);
    let _ = Request::from_frame(&mut cursor);
});
