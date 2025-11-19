# task-23B - Implement SIGQ Wire Format

## Description

Create wire format type wrapper for Falcon-512-padded signatures (666 bytes) with full serialization support. This type provides type-safe handling of post-quantum cryptographic signatures at the protocol layer. Note: PUBQ (public key) is not needed as it is not used in the CERQ structure.

**Dependencies**: Requires Task 23A (Tag enum) complete.

## Acceptance Criteria

- [ ] File created: `roughenough-protocol/src/tags/sigq.rs` with:
  ```rust
  pub struct Sigq(FixedTag<666>);
  ```
- [ ] ToWire and FromWire traits implemented for Sigq
- [ ] Module exports added to `roughenough-protocol/src/tags/mod.rs`
- [ ] Compile-time size validation with const assertion:
  - `const_assert_eq!(size_of::<Sigq>(), 666);`
- [ ] Test: `sigq_wire_roundtrip()` verifies 666-byte signature serialization
- [ ] Test: `sigq_default()` verifies default construction creates 666 zero bytes
- [ ] Test: `falcon_signature_size_matches_pqcrypto()` validates size matches pqcrypto-falcon library
- [ ] All tests pass: `cargo test -p roughenough-protocol sigq`
