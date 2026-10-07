use std::net::SocketAddr;

use roughenough_common::crypto::make_srv_commitment;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::{REQUEST_SIZE, Request};
use roughenough_protocol::tags::{ProtocolVersion, PublicKey, SrvCommitment};
use roughenough_protocol::wire::FromFrame;

use crate::metrics::types::RequestMetrics;
use crate::responses::ResponseHandler;

pub struct RequestHandler {
    responder: ResponseHandler,
    metrics: RequestMetrics,
    /// SRV commitment to this server's long-term key, H(0xff || public_key)
    srv_commitment: SrvCommitment,
}

impl RequestHandler {
    pub fn new(handler: ResponseHandler) -> Self {
        let srv_commitment = make_srv_commitment(&handler.long_term_public_key());

        Self {
            responder: handler,
            metrics: RequestMetrics::default(),
            srv_commitment,
        }
    }

    pub fn collect_request(&mut self, request_bytes: &mut [u8], src_addr: SocketAddr) {
        // RFC 5.1: request size SHOULD be at least 1024 bytes for UDP; this
        // implementation requires it. Larger requests are accepted up to a
        // full MTU payload (the receive buffer is MAX_REQUEST_SIZE bytes).
        if request_bytes.len() < REQUEST_SIZE {
            self.metrics.num_runt_requests += 1;
            return;
        } else if request_bytes.len() > REQUEST_SIZE {
            self.metrics.num_oversized_requests += 1;
        }

        let mut cursor = ParseCursor::new(request_bytes);
        match Request::from_frame(&mut cursor) {
            Ok(request) => {
                // RFC 5.2: a request committing to a long-term key this server
                // does not hold MUST be ignored
                if let Some(srv) = request.srv()
                    && srv != &self.srv_commitment
                {
                    self.metrics.num_srv_mismatch += 1;
                    return;
                }

                // RFC 5.1.1: a request offering no version in common with this
                // server MAY be ignored; this implementation ignores it
                let Some(version) = ProtocolVersion::negotiate(request.ver().versions()) else {
                    self.metrics.num_no_common_version += 1;
                    return;
                };

                self.responder
                    .add_request(request_bytes, request, version, src_addr);
                self.metrics.num_ok_requests += 1;
            }
            Err(_) => {
                self.metrics.num_bad_requests += 1;
            }
        }
    }

    pub fn generate_responses<F>(&mut self, callback: F)
    where
        F: FnMut(SocketAddr, &[u8]),
    {
        self.responder.process_responses(callback);
        self.responder.clear();
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
    pub fn response_metrics(&self) -> crate::metrics::types::ResponseMetrics {
        self.responder.metrics()
    }
}

#[cfg(test)]
mod tests {
    use roughenough_protocol::request::MAX_REQUEST_SIZE;
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
        assert_eq!(metrics.num_oversized_requests, 0);
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
    fn oversized_garbage_request_is_rejected_as_bad() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut large_request = vec![0u8; REQUEST_SIZE + 1];

        handler.collect_request(&mut large_request, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_oversized_requests, 1);
        assert_eq!(metrics.num_bad_requests, 1);
    }

    #[test]
    fn oversized_valid_request_is_answered() {
        // A valid 1024-byte request with trailing bytes beyond the declared
        // frame length parses the same as its 1024-byte prefix
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let mut request_bytes = create_test_request_bytes(42);
        request_bytes.resize(MAX_REQUEST_SIZE, 0);

        handler.collect_request(&mut request_bytes, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_oversized_requests, 1);
        assert_eq!(metrics.num_bad_requests, 0);

        let mut responses = Vec::new();
        handler.generate_responses(|_, bytes| responses.push(bytes.to_vec()));
        assert_eq!(responses.len(), 1, "oversized request must be answered");
    }

    #[test]
    fn full_mtu_request_is_answered() {
        // A well-formed request occupying the full MTU payload: the frame's
        // declared length covers all 1472 bytes via a larger ZZZZ value
        let zzzz_len = MAX_REQUEST_SIZE - 84; // 84 = framing + header + VER/NONC/TYPE
        let entries: &[(&[u8; 4], Vec<u8>)] = &[
            (b"VER\x00", 0x00000001u32.to_le_bytes().to_vec()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; zzzz_len]),
        ];
        let mut request_bytes = build_raw_request(entries);
        assert_eq!(request_bytes.len(), MAX_REQUEST_SIZE);

        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        handler.collect_request(&mut request_bytes, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_oversized_requests, 1);

        let mut responses = Vec::new();
        handler.generate_responses(|_, bytes| responses.push(bytes.to_vec()));
        assert_eq!(responses.len(), 1, "full-MTU request must be answered");
    }

    #[test]
    fn mismatched_srv_request_is_dropped() {
        // RFC 5.2: when a request's SRV tag does not match a long-term key held
        // by this server, the request MUST be ignored
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let wrong_commitment = roughenough_protocol::tags::SrvCommitment::from([0xab; 32]);
        let nonce = Nonce::from([7u8; 32]);
        let request = Request::new_with_server(&nonce, &wrong_commitment);
        let mut request_bytes = request.as_frame_bytes().unwrap();

        handler.collect_request(&mut request_bytes, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_srv_mismatch, 1);

        let mut responses = Vec::new();
        handler.generate_responses(|_, bytes| responses.push(bytes.to_vec()));
        assert!(responses.is_empty(), "mismatched SRV must not be answered");
    }

    #[test]
    fn matching_srv_request_is_answered() {
        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let commitment = roughenough_common::crypto::make_srv_commitment(
            &handler.responder.long_term_public_key(),
        );
        let nonce = Nonce::from([7u8; 32]);
        let request = Request::new_with_server(&nonce, &commitment);
        let mut request_bytes = request.as_frame_bytes().unwrap();

        handler.collect_request(&mut request_bytes, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_srv_mismatch, 0);

        let mut responses = Vec::new();
        handler.generate_responses(|_, bytes| responses.push(bytes.to_vec()));
        assert_eq!(responses.len(), 1, "matching SRV must be answered");
    }

    /// Build a framed request from raw (tag, value) entries. Caller is
    /// responsible for tag ordering and sizing values to total 1024 bytes.
    fn build_raw_request(entries: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
        use roughenough_protocol::util::test_utils::{build_msg, frame};

        let entries: Vec<([u8; 4], Vec<u8>)> =
            entries.iter().map(|(t, v)| (**t, v.clone())).collect();
        frame(&build_msg(&entries))
    }

    #[test]
    fn request_with_no_common_version_is_dropped() {
        // RFC 5.1.1: if the VER list contains no version supported by the
        // server, it MAY ignore the request (this implementation's choice)
        let entries: &[(&[u8; 4], Vec<u8>)] = &[
            (b"VER\x00", 0x00000005u32.to_le_bytes().to_vec()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; 940]),
        ];
        let mut request_bytes = build_raw_request(entries);
        assert_eq!(request_bytes.len(), REQUEST_SIZE);

        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        handler.collect_request(&mut request_bytes, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_no_common_version, 1);

        let mut responses = Vec::new();
        handler.generate_responses(|_, bytes| responses.push(bytes.to_vec()));
        assert!(responses.is_empty(), "no common version: not answered");
    }

    #[test]
    fn response_version_is_negotiated() {
        use roughenough_protocol::response::Response;
        use roughenough_protocol::tags::ProtocolVersion;
        use roughenough_protocol::wire::FromFrame;

        // Any offer that includes version 1 is answered with version 1
        let cases = [
            vec![0x00000001u32],
            vec![0x00000001u32, 0x8000000cu32],
            vec![0x00000001u32, 0x8000000bu32],
            vec![0x00000000u32, 0x00000001u32, 0x8000000cu32],
        ];

        for offered in cases {
            let mut ver_value = Vec::new();
            for v in &offered {
                ver_value.extend_from_slice(&v.to_le_bytes());
            }
            let pad = 940 - (ver_value.len() - 4);
            let entries: &[(&[u8; 4], Vec<u8>)] = &[
                (b"VER\x00", ver_value),
                (b"NONC", vec![0x42; 32]),
                (b"TYPE", 0u32.to_le_bytes().to_vec()),
                (b"ZZZZ", vec![0; pad]),
            ];
            let mut request_bytes = build_raw_request(entries);
            assert_eq!(request_bytes.len(), REQUEST_SIZE);

            let mut handler = create_request_handler();
            let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            handler.collect_request(&mut request_bytes, addr);
            assert_eq!(handler.metrics().num_ok_requests, 1);

            let mut responses = Vec::new();
            handler.generate_responses(|_, bytes| responses.push(bytes.to_vec()));
            assert_eq!(responses.len(), 1);

            let mut cursor = ParseCursor::new(&mut responses[0]);
            let response = Response::from_frame(&mut cursor).unwrap();

            assert_eq!(
                *response.srep().ver(),
                ProtocolVersion::RFC,
                "offered {offered:x?}"
            );
            assert_eq!(
                response.srep().vers().versions(),
                &ProtocolVersion::ADVERTISED,
                "VERS must contain all advertised versions"
            );
        }
    }

    #[test]
    fn only_version_one_requests_are_answered() {
        use roughenough_protocol::response::Response;
        use roughenough_protocol::wire::FromFrame;

        let mut handler = create_request_handler();

        // The pre-RFC draft version parses but is not negotiated; other
        // experimental-range versions are unknown. Neither is answered.
        for (port, wire_ver, nonce_byte) in [
            (8001u16, 0x8000000cu32, 0x41u8),
            (8002, 0x00000001, 0x42),
            (8003, 0x8000000b, 0x43),
            (8004, 0xbfffffff, 0x44),
        ] {
            collect_one_version(&mut handler, wire_ver, nonce_byte, port);
        }

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_no_common_version, 3);

        let mut responses = Vec::new();
        handler.generate_responses(|addr, bytes| responses.push((addr, bytes.to_vec())));
        assert_eq!(responses.len(), 1);

        let (addr, bytes) = &mut responses[0];
        assert_eq!(addr.port(), 8002);
        let mut cursor = ParseCursor::new(bytes);
        let response = Response::from_frame(&mut cursor).unwrap();
        assert_eq!(*response.srep().ver(), ProtocolVersion::RFC);
        assert_eq!(response.nonc(), &Nonce::from([0x42; 32]));
    }

    #[test]
    fn private_use_version_gets_no_response() {
        // RFC 12.2: 0xc0000000-0xffffffff is private use.
        let entries: &[(&[u8; 4], Vec<u8>)] = &[
            (b"VER\x00", 0xc0000001u32.to_le_bytes().to_vec()),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; 940]),
        ];
        let mut request_bytes = build_raw_request(entries);
        assert_eq!(request_bytes.len(), REQUEST_SIZE);

        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        handler.collect_request(&mut request_bytes, addr);

        let metrics = handler.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_no_common_version, 1);

        let mut responses = Vec::new();
        handler.generate_responses(|_, bytes| responses.push(bytes.to_vec()));
        assert!(responses.is_empty(), "private-use version: not answered");
    }

    fn collect_one_version(handler: &mut RequestHandler, wire_ver: u32, nonce_byte: u8, port: u16) {
        let entries: &[(&[u8; 4], Vec<u8>)] = &[
            (b"VER\x00", wire_ver.to_le_bytes().to_vec()),
            (b"NONC", vec![nonce_byte; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"ZZZZ", vec![0; 940]),
        ];
        let mut request_bytes = build_raw_request(entries);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        handler.collect_request(&mut request_bytes, addr);
    }

    #[test]
    fn request_with_unknown_tag_is_answered() {
        // RFC 5.1: "Unknown tags MUST be ignored by the server."
        // Tag order by little-endian value: VER < NONC < TYPE < GREZ < ZZZZ
        let entries: &[(&[u8; 4], Vec<u8>)] = &[
            (
                b"VER\x00",
                ProtocolVersion::RFC.as_u32().to_le_bytes().to_vec(),
            ),
            (b"NONC", vec![0x42; 32]),
            (b"TYPE", 0u32.to_le_bytes().to_vec()),
            (b"GREZ", vec![0xaa; 4]),
            (b"ZZZZ", vec![0; 928]),
        ];

        let mut request_bytes = build_raw_request(entries);
        assert_eq!(request_bytes.len(), REQUEST_SIZE);

        let mut handler = create_request_handler();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        handler.collect_request(&mut request_bytes, addr);

        assert_eq!(handler.metrics().num_ok_requests, 1);
        assert_eq!(handler.metrics().num_bad_requests, 0);

        let mut responses = Vec::new();
        handler.generate_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });
        assert_eq!(responses.len(), 1, "the request must be answered");
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
