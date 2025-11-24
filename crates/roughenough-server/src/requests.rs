use std::net::SocketAddr;
use std::time::Duration;

use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::{REQUEST_SIZE, Request};
use roughenough_protocol::tags::PublicKey;
use roughenough_protocol::wire::FromFrame;

use crate::metrics::request::RequestMetrics;
use crate::responses::ResponseHandler;

pub struct RequestHandler {
    responder: ResponseHandler,
    metrics: RequestMetrics,
}

impl RequestHandler {
    pub fn new(handler: ResponseHandler) -> Self {
        Self {
            responder: handler,
            metrics: RequestMetrics::default(),
        }
    }

    pub fn collect_request(&mut self, request_bytes: &mut [u8], src_addr: SocketAddr) {
        // Reject requests != 1024 bytes
        if request_bytes.len() < REQUEST_SIZE {
            self.metrics.num_runt_requests += 1;
            return;
        } else if request_bytes.len() > REQUEST_SIZE {
            self.metrics.num_jumbo_requests += 1;
            return;
        }

        let mut cursor = ParseCursor::new(request_bytes);
        match Request::from_frame(&mut cursor) {
            Ok(request) => {
                self.responder.add_request(request_bytes, request, src_addr);
                self.metrics.num_ok_requests += 1;
            }
            Err(_) => {
                self.metrics.num_bad_requests += 1;
            }
        }
    }

    /// Generate responses for all collected requests.
    ///
    /// Returns the batch size if there were requests to process, or None if empty.
    /// The caller should record batch timing via `record_batch_timing` after flushing I/O.
    pub fn generate_responses<F>(&mut self, callback: F) -> Option<u8>
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        let batch_size = self.responder.process_responses(callback);
        self.responder.clear();
        batch_size
    }

    /// Record batch timing after all I/O operations (including flush) are complete.
    pub fn record_batch_timing(&mut self, batch_size: u8, elapsed: Duration) {
        self.responder.record_batch_timing(batch_size, elapsed);
    }

    pub fn replace_online_key(&mut self) {
        self.responder.replace_online_key();
    }

    pub fn public_key(&self) -> PublicKey {
        self.responder.public_key()
    }

    #[allow(dead_code)] // used in tests, but compiler can't see that
    pub fn metrics(&self) -> RequestMetrics {
        self.metrics
    }

    #[allow(dead_code)] // used in tests, but compiler can't see that
    pub fn reset_metrics(&mut self) {
        self.metrics = RequestMetrics::default();
        self.responder.reset_metrics();
    }

    #[allow(dead_code)] // used in worker metrics collection
    pub fn response_metrics(&self) -> crate::metrics::response::ResponseMetrics {
        self.responder.metrics()
    }
}

#[cfg(test)]
mod tests {
    use roughenough_protocol::tags::Nonce;
    use roughenough_protocol::wire::ToFrame;

    use super::*;
    use crate::test_utils::new_response_handler;

    fn create_request_handler() -> RequestHandler {
        let responder = new_response_handler();
        RequestHandler::new(responder)
    }

    fn create_test_request_bytes(nonce_value: u8) -> Vec<u8> {
        let nonce = Nonce::from([nonce_value; 32]);
        let request = Request::new(&nonce);

        let bytes = request.as_frame_bytes().unwrap();
        assert_eq!(bytes.len(), REQUEST_SIZE);
        bytes
    }

    #[test]
    fn test_process_valid_request() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        handler.collect_request(&mut request_bytes, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_bad_requests, 0);
        assert_eq!(metrics.num_runt_requests, 0);
        assert_eq!(metrics.num_jumbo_requests, 0);
    }

    #[test]
    fn test_process_runt_request() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut short_request = vec![0u8; REQUEST_SIZE - 1];

        handler.collect_request(&mut short_request, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_runt_requests, 1);
    }

    #[test]
    fn test_process_jumbo_request() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut large_request = vec![0u8; REQUEST_SIZE + 1];

        handler.collect_request(&mut large_request, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_jumbo_requests, 1);
    }

    #[test]
    fn test_generate_responses() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        handler.collect_request(&mut request_bytes, addr);

        let mut responses = Vec::new();
        handler.generate_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

        assert_eq!(responses.len(), 1);
        let (response_addr, response_bytes) = &responses[0];
        assert_eq!(*response_addr, addr);
        assert!(response_bytes.starts_with(b"ROUGHTIM"));
    }

    #[test]
    fn test_metrics_reset() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        handler.collect_request(&mut request_bytes, addr);
        assert_eq!(handler.metrics().num_ok_requests, 1);

        handler.reset_metrics();
        assert_eq!(handler.metrics().num_ok_requests, 0);
    }
}
