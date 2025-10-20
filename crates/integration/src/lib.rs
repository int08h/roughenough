#![forbid(unsafe_code)]

mod load_gen;

#[cfg(test)]
mod integration_tests {
    //! These tests verify that the server's request processing and response generation
    //! paths are compatible with the client. They test the complete end-to-end flow
    //! from request processing through response generation and client-side validation.
    //!
    //! These tests are not exhaustive and do not cover all possible edge cases.
    //! They are intended to catch regressions and verify that the server's behavior
    //! matches the client's expectations.

    use std::net::SocketAddr;

    use client::validation::ResponseValidator;
    use protocol::cursor::ParseCursor;
    use protocol::request::Request;
    use protocol::response::Response;
    use protocol::tags::{Nonce, PublicKey};
    use protocol::wire::{FromWire, ToWire};
    use server::test_utils::TestContext;

    /// Validates a response against its originating request using the client `ResponseValidator`
    /// and `LongTermKey`'s public key.
    fn validate_response(
        request_bytes: &[u8],
        response_bytes: &[u8],
        pub_key: PublicKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(response_bytes.starts_with(b"ROUGHTIM"));
        // Skip framing: 8-byte "ROUGHTIM" + 4-byte length
        let mut buf = response_bytes[12..].to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let response = Response::from_wire(&mut cursor)?;

        let validator = ResponseValidator::new_with_key(pub_key);
        validator.validate(request_bytes, &response)?;
        Ok(())
    }

    /// Creates a test request with a Nonce based on a repeated single byte.
    fn create_test_request(nonce_byte: u8) -> Request {
        let nonce = Nonce::from([nonce_byte; 32]);
        Request::new(&nonce)
    }

    /// Tests that a single request generates a valid response.
    /// For single-element trees, the Merkle path is empty since there are no siblings, and the
    /// client will verify that the request nonce hashes to the signed root.
    #[test]
    fn single_request_validation() {
        let mut test_context = TestContext::new(64);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let request = create_test_request(42);
        let request_bytes = request.as_bytes().unwrap();
        test_context
            .response_handler
            .add_request(&request_bytes, request, addr);

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        assert_eq!(responses.len(), 1);
        let (response_addr, response_bytes) = &responses[0];
        assert_eq!(*response_addr, addr);

        let pub_key = test_context.key_source.public_key();

        validate_response(&request_bytes, response_bytes, pub_key).unwrap();
    }

    /// Stress tests the responder with a batch of 64 requests. This is an expected (but maximum)
    /// batch size that the server supports.
    #[test]
    fn large_batch_validation() {
        let num_requests = 64;

        let mut test_context = TestContext::new(num_requests as u8);

        let mut request_data = Vec::new();

        for i in 0..num_requests {
            let addr: SocketAddr = format!("127.0.0.1:{}", 8000 + i).parse().unwrap();
            let request = create_test_request((i * 37) as u8);
            let request_bytes = request.as_bytes().unwrap();

            request_data.push((request_bytes.clone(), addr));
            test_context
                .response_handler
                .add_request(&request_bytes, request, addr);
        }

        let mut responses = Vec::new();
        test_context
            .response_handler
            .process_responses(|addr, bytes| {
                responses.push((addr, bytes.to_vec()));
            });

        assert_eq!(responses.len(), num_requests);

        for (idx, (response_addr, response_bytes)) in responses.iter().enumerate() {
            let expected_addr = format!("127.0.0.1:{}", 8000 + idx)
                .parse::<SocketAddr>()
                .unwrap();
            assert_eq!(*response_addr, expected_addr);

            let (request_bytes, _) = &request_data[idx];
            let public_key = test_context.key_source.public_key();

            match validate_response(request_bytes, response_bytes, public_key) {
                Ok(_) => {} // Success
                Err(e) => {
                    println!("Response {idx} validation failed: {e}");

                    let mut buf = response_bytes[12..].to_vec();
                    let mut cursor = ParseCursor::new(&mut buf);
                    let response = Response::from_wire(&mut cursor).unwrap();

                    println!("Debug info for failed validation:");
                    println!("  Request bytes length: {}", request_bytes.len());
                    println!("  Response index: {}", response.indx());
                    println!("  Response path length: {}", response.path().as_ref().len());
                    println!(
                        "  Server root: {}",
                        data_encoding::HEXLOWER.encode(response.srep().root().as_ref())
                    );

                    // Compare with what the client computes to identify mismatch source
                    let tree = merkle::MerkleTree::new();
                    let computed_root = tree.root_from_paths(
                        response.indx() as usize,
                        request_bytes,
                        response.path(),
                    );
                    println!(
                        "  Client computed: {}",
                        data_encoding::HEXLOWER.encode(&computed_root)
                    );

                    panic!("Validation failed for response {idx}: {e}");
                }
            }
        }
    }
}
