use roughenough_common::crypto::make_srv_commitment;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::{REQUEST_SIZE, Request};
use roughenough_protocol::tags::{ProtocolVersion, PublicKey, SrvCommitment};
use roughenough_protocol::wire::FromFrame;

use crate::metrics::types::RequestMetrics;

pub struct RequestValidator {
    metrics: RequestMetrics,
    /// SRV commitment to this server's long-term key, H(0xff || public_key)
    srv_commitment: SrvCommitment,
}

impl RequestValidator {
    pub fn new(long_term_key: &PublicKey) -> Self {
        let srv_commitment = make_srv_commitment(long_term_key);

        Self {
            metrics: RequestMetrics::default(),
            srv_commitment,
        }
    }

    /// Returns the parsed request and negotiated version, or `None` for a
    /// request this server does not answer (counted in the metrics).
    pub fn validate(&mut self, request_bytes: &mut [u8]) -> Option<(Request, ProtocolVersion)> {
        // RFC 5.1: request size SHOULD be at least 1024 bytes for UDP; this
        // implementation requires it. Larger requests are accepted up to a
        // full MTU payload (the receive buffer is MAX_REQUEST_SIZE bytes).
        if request_bytes.len() < REQUEST_SIZE {
            self.metrics.num_runt_requests += 1;
            return None;
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
                    return None;
                }

                // RFC 5.1.1: a request offering no version in common with this
                // server MAY be ignored; this implementation ignores it
                let Some(version) = ProtocolVersion::negotiate(request.ver().versions()) else {
                    self.metrics.num_no_common_version += 1;
                    return None;
                };

                self.metrics.num_ok_requests += 1;
                Some((request, version))
            }
            Err(_) => {
                self.metrics.num_bad_requests += 1;
                None
            }
        }
    }

    pub fn metrics(&self) -> RequestMetrics {
        self.metrics
    }

    pub fn reset_metrics(&mut self) {
        self.metrics = RequestMetrics::default();
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use roughenough_protocol::request::MAX_REQUEST_SIZE;
    use roughenough_protocol::response::Response;
    use roughenough_protocol::tags::Nonce;
    use roughenough_protocol::util::test_utils::{build_msg, frame};
    use roughenough_protocol::wire::ToFrame;

    use super::*;
    use crate::test_utils::RequestPipeline;

    fn create_test_request_bytes(nonce_value: u8) -> Vec<u8> {
        let nonce = Nonce::from([nonce_value; 32]);
        let request = Request::new(&nonce);

        let bytes = request.as_frame_bytes().unwrap();
        assert_eq!(bytes.len(), REQUEST_SIZE);
        bytes
    }

    /// A framed `REQUEST_SIZE` request built from raw tags, so tests can offer
    /// versions and tags that `Request` cannot express.
    fn raw_request(versions: &[u32], nonce: u8, extra: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
        sized_raw_request(REQUEST_SIZE, versions, nonce, extra)
    }

    /// VER, NONC, TYPE, then `extra` (which must sort between TYPE and ZZZZ),
    /// with ZZZZ padding the frame to exactly `size` bytes
    fn sized_raw_request(
        size: usize,
        versions: &[u32],
        nonce: u8,
        extra: &[(&[u8; 4], Vec<u8>)],
    ) -> Vec<u8> {
        let mut entries = vec![
            (
                *b"VER\x00",
                versions.iter().flat_map(|v| v.to_le_bytes()).collect(),
            ),
            (*b"NONC", vec![nonce; 32]),
            (*b"TYPE", 0u32.to_le_bytes().to_vec()),
        ];
        entries.extend(extra.iter().map(|(tag, value)| (**tag, value.clone())));
        entries.push((*b"ZZZZ", Vec::new()));

        let unpadded_len = frame(&build_msg(&entries)).len();
        entries.last_mut().unwrap().1 = vec![0; size - unpadded_len];

        let bytes = frame(&build_msg(&entries));
        assert_eq!(bytes.len(), size);
        bytes
    }

    fn parse(bytes: &[u8]) -> Response {
        Response::from_frame_bytes(bytes).unwrap()
    }

    #[test]
    fn test_process_valid_request() {
        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        pipeline.collect(&mut request_bytes, addr);

        let metrics = pipeline.validator.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_bad_requests, 0);
        assert_eq!(metrics.num_runt_requests, 0);
        assert_eq!(metrics.num_oversized_requests, 0);
    }

    #[test]
    fn test_process_runt_request() {
        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut short_request = vec![0u8; REQUEST_SIZE - 1];

        pipeline.collect(&mut short_request, addr);

        let metrics = pipeline.validator.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_runt_requests, 1);
    }

    #[test]
    fn oversized_garbage_request_is_rejected_as_bad() {
        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut large_request = vec![0u8; REQUEST_SIZE + 1];

        pipeline.collect(&mut large_request, addr);

        let metrics = pipeline.validator.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_oversized_requests, 1);
        assert_eq!(metrics.num_bad_requests, 1);
    }

    #[test]
    fn oversized_valid_request_is_answered() {
        // A valid 1024-byte request with trailing bytes beyond the declared
        // frame length parses the same as its 1024-byte prefix
        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let mut request_bytes = create_test_request_bytes(42);
        request_bytes.resize(MAX_REQUEST_SIZE, 0);

        pipeline.collect(&mut request_bytes, addr);

        let metrics = pipeline.validator.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_oversized_requests, 1);
        assert_eq!(metrics.num_bad_requests, 0);

        let responses = pipeline.drain();
        assert_eq!(responses.len(), 1, "oversized request must be answered");
    }

    #[test]
    fn full_mtu_request_is_answered() {
        // A well-formed request occupying the full MTU payload: the frame's
        // declared length covers all 1472 bytes via a larger ZZZZ value
        let mut request_bytes = sized_raw_request(MAX_REQUEST_SIZE, &[0x00000001], 0x42, &[]);

        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        pipeline.collect(&mut request_bytes, addr);

        let metrics = pipeline.validator.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_oversized_requests, 1);

        let responses = pipeline.drain();
        assert_eq!(responses.len(), 1, "full-MTU request must be answered");
    }

    #[test]
    fn mismatched_srv_request_is_dropped() {
        // RFC 5.2: when a request's SRV tag does not match a long-term key held
        // by this server, the request MUST be ignored
        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let wrong_commitment = roughenough_protocol::tags::SrvCommitment::from([0xab; 32]);
        let nonce = Nonce::from([7u8; 32]);
        let request = Request::new_with_server(&nonce, &wrong_commitment);
        let mut request_bytes = request.as_frame_bytes().unwrap();

        pipeline.collect(&mut request_bytes, addr);

        let metrics = pipeline.validator.metrics();
        assert_eq!(metrics.num_ok_requests, 0);
        assert_eq!(metrics.num_srv_mismatch, 1);

        let responses = pipeline.drain();
        assert!(responses.is_empty(), "mismatched SRV must not be answered");
    }

    #[test]
    fn matching_srv_request_is_answered() {
        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let commitment = roughenough_common::crypto::make_srv_commitment(
            &pipeline.responder.long_term_public_key(),
        );
        let nonce = Nonce::from([7u8; 32]);
        let request = Request::new_with_server(&nonce, &commitment);
        let mut request_bytes = request.as_frame_bytes().unwrap();

        pipeline.collect(&mut request_bytes, addr);

        let metrics = pipeline.validator.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_srv_mismatch, 0);

        let responses = pipeline.drain();
        assert_eq!(responses.len(), 1, "matching SRV must be answered");
    }

    #[test]
    fn response_version_is_negotiated() {
        // Any offer that includes version 1 is answered with version 1
        let cases = [
            vec![0x00000001u32],
            vec![0x00000001u32, 0x8000000cu32],
            vec![0x00000001u32, 0x8000000bu32],
            vec![0x00000000u32, 0x00000001u32, 0x8000000cu32],
        ];

        for offered in cases {
            let mut request_bytes = raw_request(&offered, 0x42, &[]);

            let mut pipeline = RequestPipeline::new(64);
            let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            pipeline.collect(&mut request_bytes, addr);
            assert_eq!(pipeline.validator.metrics().num_ok_requests, 1);

            let responses = pipeline.drain();
            assert_eq!(responses.len(), 1);

            let response = parse(&responses[0].1);

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
        let mut pipeline = RequestPipeline::new(64);

        // The pre-RFC draft version parses but is not negotiated; other
        // experimental-range versions are unknown. Neither is answered.
        // RFC 5.1.1: if the VER list contains no version supported by the
        // server, it MAY ignore the request (this implementation's choice).
        for (port, wire_ver, nonce_byte) in [
            (8001u16, 0x8000000cu32, 0x41u8),
            (8002, 0x00000001, 0x42),
            (8003, 0x8000000b, 0x43),
            (8004, 0xbfffffff, 0x44),
            (8005, 0x00000005, 0x45),
            // RFC 12.2: 0xc0000000-0xffffffff is private use
            (8006, 0xc0000001, 0x46),
        ] {
            let mut request_bytes = raw_request(&[wire_ver], nonce_byte, &[]);
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            pipeline.collect(&mut request_bytes, addr);
        }

        let metrics = pipeline.validator.metrics();
        assert_eq!(metrics.num_ok_requests, 1);
        assert_eq!(metrics.num_no_common_version, 5);

        let responses = pipeline.drain();
        assert_eq!(responses.len(), 1);

        let (addr, bytes) = &responses[0];
        assert_eq!(addr.port(), 8002);
        let response = parse(bytes);
        assert_eq!(*response.srep().ver(), ProtocolVersion::RFC);
        assert_eq!(response.nonc(), &Nonce::from([0x42; 32]));
    }

    #[test]
    fn request_with_unknown_tag_is_answered() {
        // RFC 5.1: "Unknown tags MUST be ignored by the server."
        // Tag order by little-endian value: VER < NONC < TYPE < GREZ < ZZZZ
        let mut request_bytes = raw_request(
            &[ProtocolVersion::RFC.as_u32()],
            0x42,
            &[(b"GREZ", vec![0xaa; 4])],
        );

        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        pipeline.collect(&mut request_bytes, addr);

        assert_eq!(pipeline.validator.metrics().num_ok_requests, 1);
        assert_eq!(pipeline.validator.metrics().num_bad_requests, 0);

        let responses = pipeline.drain();
        assert_eq!(responses.len(), 1, "the request must be answered");
    }

    #[test]
    fn response_goes_to_request_source() {
        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        pipeline.collect(&mut request_bytes, addr);

        let responses = pipeline.drain();

        assert_eq!(responses.len(), 1);
        let (response_addr, response_bytes) = &responses[0];
        assert_eq!(*response_addr, addr);
        assert!(response_bytes.starts_with(b"ROUGHTIM"));
    }

    #[test]
    fn test_metrics_reset() {
        let mut pipeline = RequestPipeline::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut request_bytes = create_test_request_bytes(42);

        pipeline.collect(&mut request_bytes, addr);
        assert_eq!(pipeline.validator.metrics().num_ok_requests, 1);

        pipeline.validator.reset_metrics();
        assert_eq!(pipeline.validator.metrics().num_ok_requests, 0);
    }
}
