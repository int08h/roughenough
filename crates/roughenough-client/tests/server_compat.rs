//! The server's batched responses must validate with the client's `ResponseValidator`. These
//! are the only tests that check a multi-leaf batch end to end through the client validator.

use std::net::SocketAddr;

use roughenough_client::validation::ResponseValidator;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::{Nonce, ProtocolVersion, PublicKey};
use roughenough_protocol::wire::{FromFrame, ToFrame};
use roughenough_server::test_utils::TestContext;

fn validate_response(
    request_bytes: &[u8],
    response_bytes: &[u8],
    pub_key: PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let validator = ResponseValidator::new(Some(pub_key));
    validator.validate(request_bytes, response_bytes)?;
    Ok(())
}

fn create_test_request(nonce_byte: u8) -> Request {
    let nonce = Nonce::from([nonce_byte; 32]);
    Request::new(&nonce)
}

#[test]
fn single_request_validation() {
    let mut test_context = TestContext::new(64);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    let request = create_test_request(42);
    let request_bytes = request.as_frame_bytes().unwrap();
    test_context
        .response_handler
        .add_request(&request_bytes, request, ProtocolVersion::RFC, addr);

    let mut responses = Vec::new();
    test_context
        .response_handler
        .process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

    assert_eq!(responses.len(), 1);
    let (response_addr, response_bytes) = &responses[0];
    assert_eq!(*response_addr, addr);

    let response = Response::from_frame_bytes(response_bytes).unwrap();
    assert_eq!(*response.srep().ver(), ProtocolVersion::RFC);
    assert_eq!(response.srep().vers().versions(), &[ProtocolVersion::RFC]);

    let pub_key = test_context.key_source.public_key();

    validate_response(&request_bytes, response_bytes, pub_key).unwrap();
}

#[test]
fn large_batch_validation() {
    let num_requests = 64;

    let mut test_context = TestContext::new(num_requests as u8);

    let mut request_data = Vec::new();

    for i in 0..num_requests {
        let addr: SocketAddr = format!("127.0.0.1:{}", 8000 + i).parse().unwrap();
        let request = create_test_request((i * 37) as u8);
        let request_bytes = request.as_frame_bytes().unwrap();

        request_data.push((request_bytes.clone(), addr));
        test_context.response_handler.add_request(
            &request_bytes,
            request,
            ProtocolVersion::RFC,
            addr,
        );
    }

    let mut responses = Vec::new();
    test_context
        .response_handler
        .process_responses(|addr, bytes| {
            responses.push((addr, bytes.to_vec()));
        });

    assert_eq!(responses.len(), num_requests);

    let mut shared_root: Option<Vec<u8>> = None;

    for (idx, (response_addr, response_bytes)) in responses.iter().enumerate() {
        let expected_addr = format!("127.0.0.1:{}", 8000 + idx)
            .parse::<SocketAddr>()
            .unwrap();
        assert_eq!(*response_addr, expected_addr);

        let response = Response::from_frame_bytes(response_bytes).unwrap();
        assert_eq!(response.indx(), idx as u32);
        assert!(
            !response.path().as_ref().is_empty(),
            "batched response {idx} must carry a non-empty Merkle PATH"
        );

        let root = response.srep().root().as_ref().to_vec();
        match &shared_root {
            Some(expected) => assert_eq!(*expected, root, "response {idx} ROOT differs"),
            None => shared_root = Some(root),
        }

        let (request_bytes, _) = &request_data[idx];
        let public_key = test_context.key_source.public_key();

        validate_response(request_bytes, response_bytes, public_key)
            .unwrap_or_else(|e| panic!("response {idx} failed validation: {e}"));
    }
}
