---
id: task-2
title: Add comments that link the code to the RFC
status: Done
assignee: []
created_date: '2025-07-08'
updated_date: '2025-07-09'
labels: []
dependencies: []
---

## Description

The draft IETF RFC specifying the Roughtime protocol is in doc/draft-ietf-ntp-roughtime-14.txt. I would like to update
the code code to add comments that link the RFC specification to code, where adding the comments improves the reader's
comprehension of how the roughtime protocol is implemented.

DO
* Link public portions of the code back to the RFC
* Summarize, contextualize, and revise 
* Quote parts of the RFC where the specification and the code clearly correspond

DO NOT
* Copy large chunks of the RFC as comments
* Comment non-public elements
* Remove existing comments

### Examples

This example link the variable MAX_PATHs and its value '32' back to a specific RFC "MUST".
```rust
/// RFC 5.2.4 "The PATH MUST NOT contain more than 32 hash values."
pub const MAX_PATHS: usize = 32;
```

This example summarizes the RFC's intent and explains why the '5' second value was chosen. 
```rust
/// RFC 5.2.5 Default server accuracy radius in seconds.
///
/// The RADI tag represents the server's estimate of the accuracy of its MIDP (timestamp)
/// in seconds. Protocol compliant servers must ensure that the true time lies within the
/// interval (MIDP-RADI, MIDP+RADI) at the moment of processing.
///
/// The RFC states that servers without leap second information should set RADI to
/// at least 3 seconds. This implementation uses 5 seconds as a conservative default
/// to account for potential system latency and clock uncertainty. Also leap seconds suck.
pub const DEFAULT_RADI_SECONDS: u32 = 5;
```

## Acceptance Criteria

- [ ] The protocol crate has been evaluated for commenting [x]
- [ ] The merkle crate has been evaluated for commenting [x]
- [ ] The common crate has been evaluated for commenting [x]
- [ ] The keys crate has been evaluated for commenting [x]
## Implementation Plan

1. Read the RFC document to understand key specifications\n2. Review protocol crate and identify public APIs that correspond to RFC sections\n3. Review merkle crate and add appropriate RFC references\n4. Review common crate for protocol-related public elements\n5. Review keys crate for cryptographic specifications from RFC\n6. Ensure comments are concise and focus on linking code to RFC specifications

## Implementation Notes

Successfully added RFC comments linking code to the RFC specification across all four crates.

Approach taken:
- Reviewed RFC document draft-ietf-ntp-roughtime-14.txt to understand key specifications
- Systematically reviewed each crate and identified public APIs corresponding to RFC sections
- Added concise RFC references with section numbers before existing documentation
- Focused on protocol-specific elements like tags, wire formats, timestamps, and cryptographic operations

Modified files:
- protocol/src/tag.rs: Added RFC 4.1.3 and 4.2 references for tag definitions and ordering
- protocol/src/wire.rs: Added RFC 5 references for packet framing
- protocol/src/request.rs: Added RFC 5.1 reference for request size requirements
- protocol/src/response.rs: Added RFC 5.2 reference for required response tags
- protocol/src/header.rs: Added RFC 4.2 references for offset alignment and tag ordering
- protocol/src/tags/nonce.rs: Added RFC 5.1.2 reference for 32-byte nonce requirement
- protocol/src/tags/sig.rs: Added RFC 5.2.1 reference for 64-byte Ed25519 signature
- protocol/src/tags/root.rs: Added RFC 5.2.5 reference for 32-byte Merkle root
- protocol/src/tags/pubk.rs: Added RFC 5.2.6 reference for 32-byte Ed25519 public key
- protocol/src/util/clocksource.rs: Added RFC 4.1.4 reference for timestamp format
- merkle/src/lib.rs: Added RFC 5.3 references for Merkle tree construction with tweaks
- common/src/crypto.rs: Added RFC 5.1.4 reference for SRV commitment calculation
- keys/src/longterm/identity.rs: Added RFC 5.2.6 reference for key separation purpose
- keys/src/online/online.rs: Added RFC 5.2.6 reference for temporary signing key

The comments improve comprehension by directly connecting implementation details to RFC requirements without duplicating large sections of the specification.
