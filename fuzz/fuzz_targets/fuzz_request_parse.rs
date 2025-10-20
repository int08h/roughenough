#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::{Request, REQUEST_SIZE};
use roughenough_protocol::tags::{Nonce, SrvCommitment};
use roughenough_protocol::wire::{FromFrame, ToFrame};

// Simple structure for generating valid-looking requests
#[derive(Arbitrary)]
struct FuzzRequestData {
    use_srv: bool,
    nonce: [u8; 32],
    srv: Option<[u8; 32]>,
}

fuzz_target!(|data: &[u8]| {
    // Try structure-aware fuzzing first
    let mut u = Unstructured::new(data);
    if let Ok(fuzz_data) = FuzzRequestData::arbitrary(&mut u) {
        // Create a valid request
        let nonce = Nonce::from(fuzz_data.nonce);
        let request = if let Some(srv_commit) = fuzz_data.srv {
            let srv = SrvCommitment::from(srv_commit);
            Request::new_with_server(&nonce, &srv)
        } else {
            Request::new(&nonce)
        };
        
        // Encode to framed wire format
        let mut buffer = vec![0u8; REQUEST_SIZE];
        let mut cursor = ParseCursor::new(&mut buffer);
        
        if request.to_frame(&mut cursor).is_ok() {
            // Parse it back
            let mut parse_cursor = ParseCursor::new(&mut buffer);
            let _ = Request::from_frame(&mut parse_cursor);
        }
    }
    
    // Continue with raw fuzzing cuz I'm simple
    let mut data_copy = data.to_vec();
    let mut cursor = ParseCursor::new(&mut data_copy);
    let _ = Request::from_frame(&mut cursor);
});