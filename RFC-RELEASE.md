# RFC 10049 Release Plan (2.1.0)

RFC 10049 was published on 2026-10-05. It replaces draft-ietf-ntp-roughtime-19.
This document records the decisions for the release that aligns roughenough
with the published RFC, and the work needed to implement them.

## What changed from draft-19 to RFC 10049

Most of the changes are editorial. Section numbers did not change, so the
existing "RFC x.y.z" references in the code are still correct. These are the
changes that affect the implementation:

1. **Signature context strings changed case (wire-breaking).** Sections
   5.2.1 and 5.2.6 now say `"Roughtime v1 response signature"` and
   `"Roughtime v1 delegation signature"`. Draft-19 said `"RoughTime ..."`.
   The change came from an RFC Editor consistency edit during Final Review
   (FinalReview-rfc10049 issue #5). There are no errata as of 2026-10-06.
2. **Version 0x8000000c is no longer defined.** The RFC editor note that
   assigned it as the draft test version was removed. 0x80000000-0xbfffffff
   is now "Reserved for Experimental Use" (Section 12.2).
3. **The server-list `"version"` field is an integer** (Section 8.3). The
   draft note that allowed other representations, including 30006, was
   removed.
4. **IANA assigned port 5319** for both TCP and UDP (Section 12.1).
5. **Grease (Section 7)** now says the invalid signature can be on either
   SREP or DELE. This is a clarification only.

## Decisions

| # | Topic | Decision |
|---|-------|----------|
| 1 | Scope | Fix only what changed from draft-19 to the RFC. `MAX_VERSIONS = 8` and UDP-only transport stay as documented deviations. |
| 2 | Server: draft 0x8000000c | Drop it. The server negotiates and advertises only v1. |
| 3 | Server-list `"version"` | Parse as `Integer(u32) \| Legacy(String)`. Accept both forms and interpret neither. |
| 4 | Default port | 5319. |
| 5 | Protocol reference doc | `doc/RFC-PROTOCOL.md` stays deleted. References point at `doc/RFC-10049.txt`. |
| 6 | Experimental range | Reject everything except 0x8000000c on parse. The server does not accept arbitrary experimental versions. |
| 7 | Request with no common version | Ignore it silently (current behavior). |
| 8 | Release version | 2.1.0. The CHANGELOG notes the breaking changes, including the public API removals in `roughenough-protocol`. |
| 9 | Test fixtures | Generate new v1 fixtures. Keep the existing 0x8000000c capture as the positive test for the draft profile. |
| 10 | Reporting server | Accept reports for both v1 and 0x8000000c. |
| 11 | v1 context strings | Use `Roughtime`, as in the RFC text. |
| 12 | Client default | Offer v1 by default, and let users opt into 0x8000000c. |
| 13 | Client opt-in drafts | 0x8000000c only. |
| 14 | Client `-P/--protocol` values | `1` (default), `both`, and `19`. |
| 15 | Where version policy lives | The protocol crate parses {0x1, 0x8000000c}. Server negotiation accepts only {0x1}. |
| 16 | Disclosure | The CHANGELOG and README say that this implementation uses the RFC v1 context strings. They do not mention other draft implementations or future interop. |

## Work items

### Protocol crate (`roughenough-protocol`)

- [x] `ProtocolVersion::from_u32` accepts only 0x1 and 0x8000000c. All other
      values fail to parse, including 0x0 and the rest of the experimental
      range.
- [x] Make the context strings depend on the version:
  - v1: `b"Roughtime v1 response signature\x00"` and
    `b"Roughtime v1 delegation signature\x00"`
  - 0x8000000c: `b"RoughTime v1 response signature\x00"` and
    `b"RoughTime v1 delegation signature\x00"`
- [x] Remove the arbitrary-experimental machinery: the `is_draft` range
      check, the draft ranking in `preference()`, and the draft range
      constants.
- [x] Fix the doc comment on `ProtocolVersion::RFC` ("(soon to be)
      assigned").
- [x] Change `default_offered_versions()` in `request.rs` to `[RFC]`.
- [x] Update the comments that describe 0x80000000-0xbfffffff as the
      "draft/experimental" range that is accepted.
- [x] Update the fuzz targets (`fuzz_structured.rs`) to stop generating
      arbitrary experimental versions.

### Server (`roughenough-server`, `roughenough-keys`)

- [x] Negotiate only v1. VERS advertises `[0x1]`.
- [x] Requests that do not offer v1 are ignored silently.
- [x] Remove the per-batch slot logic for off-list drafts in
      `responses.rs`, and the related caps and tests in `requests.rs`.
- [x] Sign SREP and DELE with the v1 context strings.
- [x] Change the default port to 5319 in `args.rs`.
- [x] Update `Dockerfile` `EXPOSE` and `CMD` to 5319.

### Client (`roughenough-client`)

- [x] `-P/--protocol` values: `1` (default, offers `[0x1]`), `both` (offers
      `[0x1, 0x8000000c]`), and `19` (offers `[0x8000000c]`).
- [x] Verify each response with the context strings for the version in
      that response.
- [x] Change `ServerList` `version` to an enum
      `Integer(u32) | Legacy(String)`. Accept both forms.
- [x] Update `testdata/serverlist-*.json` to use integer versions.

### Reporting server (`roughenough-reporting-server`)

- [x] Accept reports that contain v1 or 0x8000000c responses. Use the same
      validator as the client.
- [x] Update the report fixtures so that both versions are covered.

### Tests and fixtures

- [x] Generate new v1 request and response fixtures for the positive tests.
- [x] Keep `rfc-request.071039e5` and `rfc-response.071039e5` as the
      positive tests for the 0x8000000c profile. Relabel them in
      `crates/roughenough-protocol/testdata/README.md`.
- [x] Update the tests that assume `DRAFT` is the default or that any
      experimental value is accepted. Do not disable or ignore tests.
- [x] Add tests: v1 signatures verify only with `Roughtime`, and
      0x8000000c signatures verify only with `RoughTime`.
- [x] Integration test: a 2.1.0 client with `--version both` against a
      2.1.0 server negotiates v1.

### Documentation

- [x] `CHANGELOG.md`: add a 2.1.0 entry. List the breaking changes: the
      dropped server support for 0x8000000c, the new default port, the
      changed client default, and the removed public API items. Say that v1
      uses the RFC 10049 context strings.
- [x] `README.md`: say that v1 uses the RFC 10049 context strings. Update
      the default port (line 74) and the example commands.
- [x] `CLAUDE.md` lines 7, 26, and 124: point at `doc/RFC-10049.txt`.
- [x] `doc/REQUEST-FLOW.md` lines 4-5: point at `doc/RFC-10049.txt`.
- [x] `SECURITY.md` line 18: cite RFC 10049.
- [x] Check `GEMINI.md` and `CONTRIBUTING.md` for draft references.

### Release

- [x] Bump the workspace version and `roughenough-reporting-server` to
      2.1.0.
- [x] Run `cargo +nightly fmt`, `cargo clippy`, `cargo test --workspace`,
      and the integration test.
- [x] Run `cargo bench -p roughenough-server` before and after the change,
      because the server request path changes.
- [ ] Follow `doc/RELEASE-CHECKLIST.md`.

## Deployment

- roughtime.int08h.com:2002 runs an old build that advertises
  `[0x0, 0x8000000c]`. Port 2003 did not answer on 2026-10-06.
- After the upgrade, the server answers only v1 on port 5319.

## Implementation notes

These differ from, or add to, the plan above.

- **Response VER check (added).** The client validator rejects a response
  whose VER the request did not offer (`ValidationError::UnofferedVersion`).
  RFC 7 lists "version numbers not in the request" as an invalid response.
  Without the check, a default client (offering only v1) would accept a
  0x8000000c response, which defeats decision 12.
- **The client flag is `-P/--protocol`**, not `--version`. `--version`
  prints the crate version.
- **Server version plumbing kept.** `ResponseHandler` still keeps one
  template per negotiated version, bounded by `ProtocolVersion::ADVERTISED`.
  The off-list draft cap, `MAX_VERSIONS_PER_BATCH`, and the unreleased
  `num_version_overflow` metric are removed. `add_request` no longer
  returns `bool`.
- **The mixed-version benchmark is removed**, because draft requests are
  now dropped before batching.
- **New v1 fixtures** `rfc10049-request.104172a3` and
  `rfc10049-response.104172a3` are generated by this server from a fixed
  seed (see `crates/roughenough-protocol/testdata/README.md`). No external
  v1 implementation was available to capture from.
- **Reporting server test** combines the real 0x8000000c capture with a
  chained v1 entry in one report.
- **Integration test** adds a negative case: a client with `-P 19` times
  out against the v1-only server.

## Benchmark results

`cargo bench -p roughenough-server --bench server_ops -- --skip network_send`
on HEAD (baseline) and on the change. `network_send` was skipped because the
sandbox blocks UDP sockets; this change does not touch the send path.
Medians in microseconds, three interleaved runs each:

| Batch | Baseline runs 1 / 2 / 3 | Change runs 1 / 2 / 3 |
|------:|-------------------------|-----------------------|
| 1  | 5.416 / 5.791 / 5.832 | 5.791 / 5.832 / 5.832 |
| 2  | 6.332 / 6.790 / 6.749 | 6.791 / 6.791 / 6.791 |
| 4  | 8.124 / 8.707 / 8.707 | 8.707 / 8.707 / 8.707 |
| 8  | 12.45 / 12.45 / 12.45 | 12.45 / 12.45 / 12.45 |
| 16 | 19.95 / 19.95 / 19.99 | 19.99 / 19.99 / 19.99 |
| 32 | 34.91 / 34.91 / 34.99 | 35.04 / 34.91 / 34.99 |
| 64 | 64.91 / 64.79 / 64.74 | 65.12 / 64.83 / 64.95 |

The baseline's own medians move between runs as much as the difference
between baseline and change. No measurable change.
