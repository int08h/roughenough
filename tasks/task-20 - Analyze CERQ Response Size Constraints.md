# task-20 - Analyze CERQ Response Size Constraints

## Description

Validate that hybrid CERQ responses (containing both Ed25519 and Falcon-512-padded signatures) can comply with the Roughtime RFC constraint that responses should not create excessive amplification. This analysis determines if the Falcon-512-padded implementation approach is viable or if protocol modifications are needed.

**IMPORTANT**: CERQ size is constant and does not vary with Merkle tree depth. The PATH tag (which varies with depth) is not part of CERQ; it appears separately in the response message.

**BLOCKER**: This task must complete successfully before proceeding with implementation tasks. If CERQ responses exceed reasonable size limits, the entire approach may need revision.

**Context**: CERQ is an opt-in extension. This analysis ensures the opt-in protocol is viable without affecting default RFC Ed25519-only behavior.

**Dependencies**: Must complete before any implementation tasks (23A-32).

## Acceptance Criteria

- [ ] Calculate CERQ tag size (constant, does not vary with depth):
  - Formula: SIG (64 bytes) + DELE (variable) + SIGQ (666 bytes)
- [ ] DELE size measured from current implementation
- [ ] CERQ size documented (PUBQ not needed, which would have added 897 bytes)
- [ ] Calculate total response size for various Merkle tree depths 0, 4, 8, 16:
  - Formula: 12 (frame) + CERQ_size + SREP_size + PATH_size(depth)
- [ ] Analysis document created showing: depth → PATH size → total response size
- [ ] Comparison table: CERT response vs CERQ response at each depth
- [ ] Decision: CERQ responses fit within reasonable size limits (<=1420 bytes for amplification prevention)
- [ ] Note: Since CERQ is constant and PATH varies, total response size scales the same way for CERT and CERQ (CERQ just adds ~666 bytes overhead for Falcon signature)
- [ ] Recommendation: Proceed with implementation OR revise approach OR abandon feature
- [ ] Results added to `doc/CERQ-SIZE-ANALYSIS.md`
