# task-29 - Add Falcon-512-padded Test Vectors

## Description

Establish cryptographic correctness using NIST Known Answer Tests (KAT) or pqcrypto-falcon reference test vectors for Falcon-512-padded. Test vectors provide regression protection and validation against the standard specification.

**Dependencies**: Requires Tasks 24 (Key generation), 25 (SeedBackend) complete.

## Acceptance Criteria

- [ ] Test vector file created: `test-vectors/falcon512-padded-kat.json` with NIST Round 3 KAT data
- [ ] Minimum 5 test vectors with: private_key (hex), public_key (hex), message (hex), signature (hex)
- [ ] Test `falcon_nist_kat_vectors_verify()` validates all test vectors using pqcrypto-falcon
- [ ] pqcrypto-falcon version pinned in all Cargo.toml files: `pqcrypto-falcon = "0.3.0"` (verify exact version)
- [ ] Test documentation references NIST source: https://csrc.nist.gov/projects/post-quantum-cryptography/round-3-submissions
- [ ] Test `falcon_cross_implementation_compatibility()` (if feasible with alternative Falcon-512-padded impl)
- [ ] All tests pass: `cargo test`
