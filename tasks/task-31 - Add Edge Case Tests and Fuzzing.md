# task-31 - Add Edge Case Tests and Fuzzing

## Description

Ensure robustness through comprehensive edge case testing and fuzzing of CERQ parsing. This validates the implementation handles malformed inputs gracefully without crashes or security issues.

**Dependencies**: Requires Tasks 23C (CERQ structure), 28 (Integration tests) complete.

## Acceptance Criteria

- [ ] Test: `cerq_with_wrong_tag_ordering()` (DELE before SIG) validates parsing rejection
- [ ] Test: `cerq_with_incorrect_offsets()` validates offset validation
- [ ] Test: `sigq_wrong_size_667_bytes()` validates fixed-size enforcement
- [ ] Test: `sigq_wrong_size_665_bytes()` validates fixed-size enforcement
- [ ] Test: `pubq_wrong_size()` validates 897-byte size enforcement
- [ ] Test: `cerq_missing_sigq_tag()` validates required tag presence
- [ ] Test: `cerq_duplicate_sig_tags()` validates unique tag requirement
- [ ] Fuzz target created: `fuzz/fuzz_targets/fuzz_cerq_parse.rs`
- [ ] Fuzz target exercises `Cerq::from_wire()` with random byte sequences
- [ ] Fuzz corpus seeded with valid CERQ messages
- [ ] Fuzz run: `cargo +nightly fuzz run fuzz_cerq_parse -- -max_total_time=600` (10 minutes)
- [ ] No crashes, no panics, no infinite loops detected
- [ ] Coverage report shows >80% code coverage of CERQ parsing logic
- [ ] All regression tests pass: `cargo test`
