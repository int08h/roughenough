# task-24 - Implement Falcon-512-padded Key Generation

## Description

Add Falcon-512-padded key generation capability to the roughenough_keys CLI tool, enabling operators to generate post-quantum key material for their Roughtime servers. Keys must be generated securely and stored using the same protection mechanisms as Ed25519 keys.

**Dependencies**: Requires Task 22 (SeedBackend design) complete.

## Acceptance Criteria

- [ ] Cargo.toml for roughenough-keys updated with `pqcrypto-falcon = "0.3.0"` dependency
- [ ] `roughenough_keys` CLI extended with `generate-falcon` subcommand
- [ ] Falcon-512-padded key-pair generated 
- [ ] Private key stored using existing envelope encryption (KMS/Secret Manager like Ed25519)
- [ ] Public key (897 bytes) output to separate file or stdout in base64 format
- [ ] Keys use `zeroize` crate to clear memory after generation
- [ ] CLI output shows: private key fingerprint, public key base64, storage location
- [ ] Test: `falcon_key_generation_produces_valid_keypair()` verifies sign/verify roundtrip with pqcrypto-falcon
- [ ] Test: `falcon_private_key_is_correct_size()` validates private key length
- [ ] Test: `falcon_keys_are_zeroized()` (if feasible with debug build memory inspection)
- [ ] Documentation added to `roughenough_keys --help` for generate-falcon command
- [ ] All tests pass: `cargo test -p roughenough-keys`
