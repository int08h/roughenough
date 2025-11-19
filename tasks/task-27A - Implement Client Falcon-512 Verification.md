# task-27A - Implement Client Falcon-512-padded Verification

## Description

Add low-level Falcon-512-padded signature verification primitives to the client validation logic, enabling clients to cryptographically verify SIGQ signatures over the hybrid SIG+DELE construction.

**Dependencies**: Requires Tasks 23B (SIGQ type), 23C (CERQ structure) complete.

## Acceptance Criteria

- [ ] `ResponseValidator` in `roughenough-client/src/validation.rs` extended with `falcon_public_key: Option<[u8; 897]>` field
- [ ] Constructor updated to accept optional Falcon-512-padded public key parameter
- [ ] Method `check_sigq_signature(&self, sig: &Signature, dele: &Dele, sigq: &Sigq) -> Result<(), ValidationError>` added
- [ ] Method extracts SIG and DELE bytes, concatenates them per Task 21 specification, verifies SIGQ using pqcrypto-falcon
- [ ] Verification uses `pqcrypto_falcon::ffi::PQCLEAN_FALCON512_CLEAN_crypto_sign_verify()`
- [ ] Test: `sigq_signature_verifies_with_valid_key()` validates correct signatures
- [ ] Test: `sigq_signature_fails_with_wrong_key()` validates key mismatch detection
- [ ] Test: `sigq_signature_fails_with_corrupted_signature()` validates tampering detection
- [ ] All tests pass: `cargo test -p roughenough-client`
