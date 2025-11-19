# task-26A - Implement Server CERQ Generation

## Description

Add opt-in server capability to generate CERQ responses when explicitly configured with a Falcon-512-padded private key. By default, the server continues to use the RFC-specified Ed25519-only signing scheme (CERT responses). Only when started with a Falcon-512-padded private key does the server switch to generating CERQ responses containing both Ed25519 and Falcon-512-padded signatures.

**Default Behavior**: Server uses RFC Ed25519-only protocol (CERT) - no changes to existing behavior.

**Opt-in Behavior**: When `--falcon-private-key` or `--falcon-key-backend` flag is provided, server switches to CERQ protocol.

**Dependencies**: Requires Tasks 23C (CERQ structure), 25 (Backend Falcon support) complete.

## Acceptance Criteria

- [ ] Server CLI accepts optional `--falcon-key-backend <backend>` flag (e.g., memory, krs)
- [ ] Server CLI accepts optional `--falcon-private-key <hex>` for MemoryBackend (testing only)
- [ ] When neither flag is provided: Server uses default RFC Ed25519-only protocol (CERT responses)
- [ ] When Falcon key flag is provided: Server switches to CERQ protocol
- [ ] LongTermIdentity in `roughenough-keys/src/longterm/identity.rs` extended with optional Falcon-512-padded private key
- [ ] Method `make_cerq()` added alongside existing `make_online_key()`:
  - Signs DELE with Ed25519 (creates SIG)
  - Concatenates context prefix + SIG + DELE bytes: `b"RoughTime v1 CERQ\0" || SIG || DELE`
  - Signs concatenated bytes with Falcon-512-padded private key (creates SIGQ)
  - Returns Cerq containing SIG, DELE, SIGQ
- [ ] Server validates Falcon private key at startup (sign + verify round-trip test)
- [ ] Server fails fast with descriptive error if Falcon key invalid: "Falcon-512-padded private key validation failed"
- [ ] Server uses CERQ only when Falcon private key is provided, CERT otherwise (explicit opt-in)
- [ ] Server logs at startup indicate protocol mode:
  - Without Falcon key: "Using RFC Ed25519-only protocol (CERT responses)"
  - With Falcon key: "Using Falcon-512-padded hybrid protocol (CERQ responses)"
- [ ] Test: `server_defaults_to_cert_without_falcon_flag()` verifies default RFC behavior
- [ ] Test: `cerq_generation_with_falcon_private_key()` verifies opt-in CERQ structure
- [ ] Test: `server_rejects_invalid_falcon_key_gracefully()` validates error handling
- [ ] All tests pass: `cargo test -p roughenough-server`
