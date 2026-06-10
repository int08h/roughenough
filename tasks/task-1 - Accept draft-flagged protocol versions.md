# task-1 - Accept draft-flagged protocol versions

Status: Done

## Description (the why)

The Roughtime RFC drafts use private-use version numbers with the high bit set
(0x80000000 | draft identifier). Clients in the wild speak several prior draft
revisions, each with its own VER value, but all post-draft-8 revisions share
identical wire behavior and signature context strings. Today the server accepts
exactly two version values (0x00000001 and 0x8000000c) and silently drops
requests from clients offering any other draft value. Accepting any
draft-flagged version lets the server interoperate with clients tracking
different draft revisions without enumerating every draft. Adapted from
upstream PR #98, reworked for the post-refactor version-negotiation machinery.

## Acceptance Criteria (the what)

- [x] A request offering any VER value with the 0x80000000 flag set (other than
      the 0xffffffff sentinel) receives a valid, verifiable response
- [x] The response SREP VER tag echoes the client's draft version, and the VERS
      list contains that version (RFC 5.2.5)
- [x] RFC version 1 (0x00000001) is preferred over any draft when both are
      offered; among drafts, the highest wire value wins
- [x] Unknown non-draft versions (e.g. 0x00000002, 0x00000000) remain ignored
- [x] A batch containing multiple distinct versions shares one Merkle tree and
      produces one SREP signature per distinct version
- [x] At most 4 distinct versions are signed per batch; requests that would
      require a 5th are dropped and counted in a metric
- [x] Existing clients offering 0x00000001 and/or 0x8000000c see no behavior
      change
- [x] Server batch-response benchmarks show no regression versus master

## Implementation Plan (the how)

1. Replace the ProtocolVersion enum with a #[repr(transparent)] newtype over
   u32 with consts RFC, RFC_DRAFT19, INVALID; add is_draft(), is_supported(),
   as_u32(); manual Debug.
2. from_u32 accepts RFC or any draft-flagged value; negotiate() filters by
   is_supported(); preference() returns u64 (RFC outranks all drafts, drafts
   ranked by wire value).
3. OnlineKey::make_srep sets VERS = [RFC, negotiated] when the negotiated
   version is outside SUPPORTED (keeps VERS at 2 entries so SREP wire size and
   the pre-sized signing buffer are unchanged).
4. ResponseHandler keys response templates by a Vec<(ProtocolVersion, Response)>
   instead of an array indexed by SUPPORTED position; cap distinct versions per
   batch at 4 with a num_version_overflow metric.
5. Mechanical const renames across all crates; update fuzz_structured target.
6. Tests: draft roundtrips and negotiation in protocol_ver.rs, version_list
   retention, make_srep VERS override in keys, server request/batch tests,
   integration end-to-end validation of a draft-version response.

## Implementation Notes (only added after working on the task)

- Approach: replaced the `ProtocolVersion` enum (Rfc/RfcDraft19/Invalid) with a
  `#[repr(transparent)]` newtype over u32 plus associated consts (RFC, DRAFT,
  INVALID; DRAFT is the single catch-all draft const, value 0x8000000c, the
  wire value the client offers and the server advertises in VERS as
  ADVERTISED = [RFC, DRAFT]). `is_draft()` is a bit test on 0x80000000 that excludes
  the 0xffffffff INVALID sentinel so the internal default can never become
  negotiable. `is_supported()` = RFC or draft. `preference()` returns u64: RFC
  ranks 1<<32, drafts rank by their draft identifier, so RFC always wins and
  the most recent draft wins among drafts.
- VERS handling: the template SREP keeps VERS = [RFC, DRAFT]; for a
  negotiated version outside SUPPORTED, `OnlineKey::make_srep` overrides VERS
  to [RFC, negotiated]. Both shapes are exactly two entries in ascending order,
  so the SREP wire size is constant, the pre-sized signing buffer remains
  valid (guarded by a debug_assert), and existing response offset tests are
  unaffected.
- Batching: `ResponseHandler` now keys response templates by a reusable
  `Vec<(ProtocolVersion, Response)>` (linear scan, batch max 64) instead of an
  array indexed by position in the advertised list, which would panic on
  off-list drafts. Distinct versions per batch are capped at
  MAX_VERSIONS_PER_BATCH = 4 (each distinct version costs one Ed25519
  signature; without a cap an adversary spraying unique draft values forces
  one signature per request). Advertised versions (RFC, DRAFT) always get a
  slot; off-list drafts compete for the remaining 2, so a flood of unique
  draft values can never starve clients offering an advertised version.
  `add_request` is #[must_use] and returns false on overflow;
  `collect_request` counts it in the new `num_version_overflow` metric. The
  cap resets per batch.
- Trade-off: worst-case signatures per batch rises from 2 to 4, bounded.
  Benchmarks (divan, median): batch_processing 1..64 and
  mixed_version_batch_processing unchanged versus master baseline (e.g. batch
  64: 69.45us -> 69.16us; mixed 64: 74.45us -> 74.45us).
- No client-side logic change was needed: the client validator derives context
  strings from the response's VER tag, and all drafts share the RFC context
  strings.
- Modified files: protocol/src/protocol_ver.rs (rewrite),
  protocol/src/{version_list.rs,request.rs,response.rs,tags/{srep,ver,vers}.rs}
  (renames + tests), keys/src/online/onlinekey.rs (VERS override),
  keys/src/lib.rs + tests/lifecycle_tests.rs (renames + draft SREP test),
  server/src/{responses.rs,requests.rs,metrics/types.rs,test_utils.rs}
  (template Vec, cap, metric, tests), server/benches/server_ops.rs,
  client/src/{args.rs,validation.rs} (renames), integration/src/lib.rs
  (draft e2e test), fuzz/fuzz_targets/fuzz_structured.rs (draft mapping).
