# task-23A - Add Falcon Tags to Protocol Enum

## Description

Add the two new post-quantum signature tags (SIGQ, CERQ) to the Tag enum with correct u32 values and wire format support. This establishes the foundation for all Falcon-512-padded wire format operations. Note: PUBQ is not needed as it is not used in the CERQ structure.

**Dependencies**: Requires Task 21 (Tag values specification) complete. Must complete before Tasks 23B, 23C.

## Acceptance Criteria

- [ ] Tag enum in `roughenough-protocol/src/tag.rs` extended with:
  ```rust
  SIGQ = 0x53494751,
  CERQ = 0x43455251,
  ```
- [ ] `Tag::from_wire()` extended with two new match arms: `b"SIGQ"`, `b"CERQ"`
- [ ] `Tag::is_nested()` updated to include `Tag::CERQ` (returns true for CERQ like CERT)
- [ ] Test `roundtrip_tag_u32()` updated to include new tags
- [ ] Test `tag_ordering()` created verifying SIG < DELE < SIGQ and CERQ < CERT
- [ ] All tests pass: `cargo test -p roughenough-protocol tag`
