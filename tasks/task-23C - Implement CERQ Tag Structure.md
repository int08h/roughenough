# task-23C - Implement CERQ Tag Structure

## Description

Create the CERQ (Certificate with Quantum signature) structure containing SIG, DELE, and SIGQ tags in correct lexicographic order with proper offset calculation. CERQ replaces CERT for servers with Falcon-512-padded capability, providing hybrid classical+quantum signature protection.

**Dependencies**: Requires Tasks 23A (Tag enum) and 23B (SIGQ/PUBQ types) complete.

## Acceptance Criteria

- [ ] File created: `roughenough-protocol/src/tags/cerq.rs` modeled after `cert.rs`
- [ ] Structure defined:
  ```rust
  const DELE_OFFSET: u32 = 64;  // size_of::<Signature>()
  const SIGQ_OFFSET: u32 = DELE_OFFSET + /* DELE size calculation */;
  const OFFSETS: [u32; 2] = [Self::DELE_OFFSET, Self::SIGQ_OFFSET];
  const TAGS: [Tag; 3] = [Tag::SIG, Tag::DELE, Tag::SIGQ];  // Must be sorted
  ```
- [ ] Constructor `Cerq::new(sig: Signature, dele: Dele, sigq: Sigq)` implemented
- [ ] Accessor methods: `sig()`, `dele()`, `sigq()` implemented
- [ ] ToWire and FromWire traits implemented
- [ ] Test: `cerq_construction()` verifies correct tag ordering
- [ ] Test: `cerq_offset_calculation()` verifies DELE and SIGQ offsets
- [ ] Test: `cerq_wire_roundtrip()` verifies serialization/deserialization
- [ ] Module export added to `roughenough-protocol/src/tags/mod.rs`
- [ ] All tests pass: `cargo test -p roughenough-protocol cerq`
