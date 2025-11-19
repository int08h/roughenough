# task-26B - Add Server CERQ Tests

## Description

Add comprehensive server-side unit tests for CERQ response generation, covering key loading, validation, error handling, and backwards compatibility scenarios. These tests focus on the server's CERQ generation logic in isolation, while task 28 covers end-to-end integration tests with actual client-server communication.

**Dependencies**: Requires Task 26A (Server CERQ generation) complete.

## Acceptance Criteria

- [ ] Test: `server_defaults_to_cert_without_falcon_key()` validates RFC default behavior (no Falcon key = CERT)
- [ ] Test: `server_loads_falcon_private_key_from_memory_backend()` validates opt-in key loading
- [ ] Test: `server_fails_gracefully_when_falcon_private_key_invalid()` checks error handling
- [ ] Test: `server_generates_valid_cerq_structure()` verifies CERQ tag ordering and offsets when Falcon key provided
- [ ] Test: `cerq_sigq_signs_correct_bytes()` validates SIGQ covers SIG + DELE per Task 21 spec
- [ ] Test: `server_batch_processing_with_cerq()` ensures batching works with CERQ responses
- [ ] Test: `server_batch_processing_with_cert()` ensures default batching unchanged
- [ ] Test: `server_startup_logs_indicate_protocol_mode()` validates startup messages show CERT vs CERQ mode
- [ ] All tests use test vectors for reproducibility
- [ ] All tests pass: `cargo test -p roughenough-server`
