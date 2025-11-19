# task-27B - Integrate CERQ Validation in Client

## Description

Add opt-in client capability to validate CERQ responses when explicitly configured with a Falcon-512-padded public key. By default, the client continues to use the RFC-specified Ed25519-only validation (CERT responses). Only when provided with a Falcon-512-padded public key does the client switch to expecting and validating CERQ responses.

**Default Behavior**: Client validates RFC Ed25519-only protocol (CERT) - no changes to existing behavior.

**Opt-in Behavior**: When `--falcon-pubkey` flag or JSON `falcon_public_key` field is provided, client expects CERQ protocol and validates both signatures.

**Protocol Mismatch Handling**:
- Client without Falcon key receiving CERQ: Accepts response (validates only SIG, ignores SIGQ) + logs INFO
- Client with Falcon key receiving CERT: Rejects response (requires CERQ when configured for Falcon) + logs ERROR

**Dependencies**: Requires Task 27A (Client verification primitives) complete.

## Acceptance Criteria

- [ ] Client CLI accepts optional `--falcon-pubkey <base64-or-hex>` flag for Falcon-512-padded public key
- [ ] Client CLI reads optional `falcon_public_key` field from JSON server list file
- [ ] When neither is provided: Client uses default RFC Ed25519-only validation (CERT)
- [ ] When Falcon public key is provided: Client switches to CERQ validation mode
- [ ] ResponseValidator detects CERQ vs CERT in response
- [ ] For CERT responses with Falcon key configured: Reject (expect CERQ when opt-in enabled)
- [ ] For CERT responses without Falcon key: Accept (default RFC behavior)
- [ ] For CERQ responses with Falcon key: Validate both SIG and SIGQ, accept only if both verify
- [ ] For CERQ responses without Falcon key: Accept (backwards compatible - validate only SIG) + log INFO "Server supports Falcon-512-padded (CERQ), validating Ed25519 only. Use --falcon-pubkey for PQ validation."
- [ ] Response rejected if Falcon key provided but server sends CERT + log ERROR "Expected CERQ but received CERT. Server may not be Falcon-enabled."
- [ ] Response rejected if either SIG or SIGQ verification fails (when validating CERQ)
- [ ] Client validates Falcon public key at startup (897 bytes, format check)
- [ ] Client fails fast with clear error if Falcon public key invalid: "Falcon-512-padded public key invalid: expected 897 bytes, got <N>"
- [ ] Test: `client_defaults_to_cert_without_falcon_flag()` verifies default RFC behavior
- [ ] Test: `client_validates_cerq_when_falcon_key_provided()` verifies opt-in validation
- [ ] Test: `client_rejects_cert_when_falcon_key_provided()` validates protocol enforcement
- [ ] Test: `client_accepts_cerq_without_falcon_key()` validates backwards compatibility
- [ ] Test: `client_rejects_valid_sig_invalid_sigq()` hybrid validation
- [ ] Test: `client_rejects_invalid_sig_valid_sigq()` hybrid validation
- [ ] All tests pass: `cargo test -p roughenough-client`
- [ ] Client `--help` updated documenting opt-in Falcon-512-padded public key usage
