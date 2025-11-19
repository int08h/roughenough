# task-28 - Add CERQ Integration Tests

## Description

Validate complete server-client interaction for both default RFC Ed25519-only protocol and opt-in Falcon-512-padded protocol through integration tests that spawn actual processes. These tests verify end-to-end communication, while task 26B covers unit tests for server CERQ generation logic. Tests must verify that the default behavior remains unchanged (RFC-compliant) and that opt-in Falcon support works correctly.

**Test Coverage**:
1. Default behavior: RFC Ed25519-only (no Falcon keys provided)
2. Opt-in behavior: Falcon-512-padded hybrid protocol (when keys provided)
3. Protocol mismatch scenarios
4. Backwards compatibility

**Dependencies**: Requires Tasks 26B (Server tests), 27B (Client integration), 29 (Test vectors) complete.

## Acceptance Criteria

### Default RFC Behavior Tests
- [ ] Test `default_server_client_cert_only()` spawns server without Falcon key, client without Falcon key
- [ ] Validates default RFC Ed25519-only protocol (CERT) works unchanged
- [ ] Test `default_server_large_batch()` validates batching works in default mode

### Opt-in Falcon Protocol Tests
- [ ] Test `falcon_server_falcon_client_cerq()` spawns server with Falcon-512-padded private key, client with Falcon-512-padded pubkey
- [ ] Validates client successfully verifies CERQ response with both signatures
- [ ] Test `falcon_cerq_large_batch_validation()` validates CERQ with 100-request batch

### Backwards Compatibility Tests
- [ ] Test `cert_client_to_falcon_server()` spawns Falcon server, non-Falcon client
- [ ] Validates non-Falcon client receives CERQ but validates only SIG (backwards compatible)
- [ ] Test `falcon_client_to_cert_server()` spawns non-Falcon server, Falcon client
- [ ] Validates Falcon client rejects CERT when configured to expect CERQ

### Mixed Mode Tests
- [ ] Test `mixed_client_pool()` spawns both CERT-only and CERQ-capable clients against Falcon-512-padded enabled server
- [ ] Validates both client types can communicate successfully

### Protocol Validation Tests
- [ ] Test `cerq_response_size_within_limits()` validates CERQ response size acceptable (from Task 20 analysis)
- [ ] Test `server_mode_indicated_in_response()` validates clients can detect server protocol mode

- [ ] All tests pass: `cargo test -p roughenough-integration`
