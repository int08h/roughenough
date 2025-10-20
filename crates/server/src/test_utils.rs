//!
//! Provides "glue" needed for complex testing scenarios
//!

use std::time::Duration;

use keys::seed::MemoryBackend;
use protocol::cursor::ParseCursor;
use protocol::request::Request;
use protocol::response::Response;
use protocol::tags::{Nonce, Version};
use protocol::util::ClockSource;
use protocol::{FromFrame, ToFrame};

use crate::keysource::KeySource;
use crate::responses::ResponseHandler;

#[allow(dead_code)]
pub struct TestContext {
    pub batch_size: u8,
    pub clock: ClockSource,
    pub response_handler: ResponseHandler,
    pub key_source: KeySource,
}

/// Creates a test ResponseHandler from a fixed seed and configuration
pub fn new_response_handler() -> ResponseHandler {
    TestContext::new(64).response_handler
}

/// Creates a TestContext so the midpoints of responses can be set to arbitrary values.
impl TestContext {
    pub fn new(batch_size: u8) -> Self {
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let seed = Box::new(MemoryBackend::from_value(&[42u8; 32]));
        let approx_90_days = Duration::from_secs(8_000_000);
        let key_source = KeySource::new(Version::RfcDraft14, seed, clock.clone(), approx_90_days);
        let response_handler = ResponseHandler::new(batch_size, key_source.clone());

        TestContext {
            batch_size,
            clock,
            response_handler,
            key_source,
        }
    }

    #[allow(dead_code)]
    pub fn create_interaction_pair(&mut self, midpoint: u64) -> (Request, Response) {
        let mut val = [0u8; 32];
        aws_lc_rs::rand::fill(&mut val).expect("should be infallible");
        let nonce = Nonce::from(val);

        self.create_interaction_pair_with_nonce(midpoint, &nonce)
    }

    #[allow(dead_code)]
    pub fn create_interaction_pair_with_nonce(
        &mut self,
        midpoint: u64,
        nonce: &Nonce,
    ) -> (Request, Response) {
        self.clock.set_time(midpoint);

        let request = Request::new(nonce);
        let request_bytes = request.as_frame_bytes().unwrap();
        let sock_addr = "127.0.0.1:8080".parse().unwrap();

        self.response_handler
            .add_request(&request_bytes, request.clone(), sock_addr);

        let mut responses = Vec::new();

        self.response_handler
            .process_responses(|_addr, response_bytes| {
                let mut bytes_copy = response_bytes.to_vec();
                let mut cursor = ParseCursor::new(&mut bytes_copy);
                let response = Response::from_frame(&mut cursor).unwrap();
                responses.push(response);
            });
        assert_eq!(responses.len(), 1, "one response was generated");

        let response = responses.pop().unwrap();
        (request, response)
    }
}
