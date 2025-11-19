# task-21 - Define Tag Values and Signing Domain

## Description

Specify exact u32 Tag enum values for SIGQ and CERQ to ensure correct lexicographic ordering in the Roughtime protocol, and define the precise cryptographic signing domain for SIGQ signatures using Falcon-512-padded. This specification is security-critical as any ambiguity in what bytes are signed could create vulnerabilities.

**Dependencies**: Must complete before Task 23A (Tag enum implementation).

## Acceptance Criteria

- [ ] Tag u32 values calculated and documented:
  - `SIGQ = 0x53494751` (ASCII "SIGQ")
  - `CERQ = 0x43455251` (ASCII "CERQ")
- [ ] Tag ordering verified: CERQ < CERT (CERQ will sort before CERT in message lists)
- [ ] CERQ internal tag ordering verified: SIG < DELE < SIGQ
- [ ] SIGQ signing domain precisely specified:
  - Input bytes: `SIG.as_ref() || DELE.as_ref()` (64 bytes SIG + variable DELE bytes)
  - Context prefix: `b"RoughTime v1 CERQ\0"` (19 bytes) for domain separation
  - Exact signing operation: `falcon_sign(private_key, b"RoughTime v1 CERQ\0" || sig_bytes || dele_bytes)`
  - Rationale: Context string provides domain separation between SIG and SIGQ signing contexts
- [ ] Justification finalized: SIGQ must sign both SIG and DELE to provide hybrid authentication (confirmed by user)
- [ ] Test vector created: Known SIG + DELE → expected SIGQ with specific Falcon-512-padded private key
- [ ] Specification added to `doc/RFC-PROTOCOL.md` under new "5.2.X SIGQ Tag" section
- [ ] Specification reviewed for cryptographic correctness (no ambiguity)
