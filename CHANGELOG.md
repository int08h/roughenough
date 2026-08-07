# Changelog

## [Unreleased]

### Security

- Client: `--set-clock` now requires `-k/--pub-key`; queries without a key
  print an unauthenticated-response warning, even in quiet mode
- Server: refuses to start without `--seed`; running with the all-zero test
  seed requires an explicit `--insecure-zero-seed` opt-in
- Server: truncated (oversized) datagrams are dropped instead of answered,
  so Merkle leaves are only computed over exactly what the client sent
- Server: private-use protocol versions (0xc0000000-0xffffffff) are no
  longer negotiated or answered (RFC 12.2)
- Keys: seed values are never written to logs, at any verbosity
- Reporting server: reports are verified to demonstrate an actual causality
  violation before storage; stored reports are capped, submissions are
  rate-limited per source IP, and request bodies are size-limited

### Fixed

- Client: saturating arithmetic on server-supplied MIDP/RADI; hostile values
  can no longer panic the client or produce false malfeasance reports
- Client: unrepresentable midpoints are displayed as a raw-value fallback
  instead of panicking
- Client: receive buffers sized to the new `MAX_RESPONSE_SIZE`; responses
  with a full 32-element PATH are no longer truncated
- Client: bracketed IPv6 literals parse in server lists; UDP datagrams are
  only sent to UDP addresses; zero values for `-n`, `-u`, and `-r` are
  rejected at argument parsing
- Client: malfeasance reports carry the full contiguous measurement chain
  and are submitted as `application/roughtime-malfeasance+json`
- Client: a duplicated or stale datagram no longer aborts a measurement
  sequence
- Keys: cloud backends (AWS/GCP KMS and secret managers) return errors
  instead of panicking; seed-load failures exit the server cleanly
- Keys: `try_choose_backend` returns errors for unavailable backends instead
  of panicking; the PKCS#11 backend is selectable end to end via
  `--seed-backend pkcs11`
- Keys: `roughenough_keys generate --key seed://...` no longer panics, and
  `store` output is directly usable as a `--seed` value
- Server: `--interface` accepts only IP addresses and says so; invalid
  values are clap errors, not panics
- Server: metrics rates are computed from per-interval deltas, not
  cumulative totals, so they no longer inflate with uptime
- Server: `Response::to_wire` bounds check accounts for frame overhead
- Server: receive errors other than WouldBlock are counted in metrics and
  return to the poll loop instead of busy-spinning
- Server: a worker thread dying shuts the server down with an error instead
  of leaving it silently degraded
- Reporting server: a first report entry carrying `rand` is accepted
  (RFC 8.4.1)
- Protocol: `UnexpectedMagic` error message shows the correct 'ROUGHTIM'
  constant (0x524f...)

### Changed

- `SeedBackend` now requires `Send`; the hand-written
  `unsafe impl Send/Sync` on the server's `KeySource` is deleted (the server
  crate carries `#![deny(unsafe_code)]` with a single documented `sendmmsg`
  exception, see Performance below)
- CLI `--version` output derives from the crate version instead of a
  hard-coded string
- Reporting server binary gained a `--listen <ADDR:PORT>` option
  (default `0.0.0.0:3000`); its storage is documented as in-memory and
  non-durable
- `roughenough-integration-test` and `roughenough-reporting-server` are
  marked `publish = false`
- Dead code removed: the unreachable non-Linux `stub_backend` in the keys
  crate's Linux KRS module

### Performance

- Server: responses are sent with one `sendmmsg` syscall per batch on Linux
  (median batch send time down 8-10% at batch sizes 16-64); other platforms
  keep the per-packet send loop. The server crate moves from
  `#![forbid(unsafe_code)]` to `#![deny(unsafe_code)]` with one documented
  Linux-only exception wrapping the syscall
- Server: per-version response templates persist across batches and
  per-request fields are set in place, removing the per-request `Response`
  clone and per-batch template rebuild (~1% at batch 64)
- Protocol: parsed `Request` structs no longer carry the always-zero ZZZZ
  padding array (1064 -> ~110 bytes); the server's `PendingRequest` stores
  only the nonce, shrinking the 64-slot pending queue from ~70 KB to ~5 KB
  (batch 64 median 87.0 -> 85.5 us). Wire bytes are unchanged (golden tests)
- Server: `MerkleTree::reserve` rounds capacity to the next power of two so
  first-batch `compute_root` never reallocates; the receive buffer is a
  handler field instead of a re-zeroed stack local; `batch_sizes` metrics
  use a fixed array, making metrics snapshots allocation-free
- Client: response validation slices signed regions out of the received
  packet in place (`find_value_range` takes `&[u8]`), removing four
  up-to-1-KB heap copies per validated response

### Simplified

- Protocol: `fixed_tag!` macro generates the NONC/ROOT/PUBK/SIG/SRV tag
  boilerplate; `SrvCommitment` and `Signature` are now `Copy`
- Protocol: `RequestedVersions`/`SupportedVersions` are type aliases of one
  `VersionList` type
- Protocol: version-independent `DELE_PREFIX`/`SREP_PREFIX` constants
  replace the per-version `dele_prefix()`/`srep_prefix()` accessors
- Merkle: `root_from_paths` is a free function; callers no longer build a
  throwaway `MerkleTree` to verify a proof
- Server: the library's modules are `#[doc(hidden)]`; the crate's public
  surface is internal to its own binary, benches, and tests

### Added

- Fuzzing: `fuzz_response_parse` exercises `Response::from_frame`; fuzz
  targets build in CI; dependabot covers `fuzz/`
- Adversarial response-parsing test suite and tests for previously untested
  tag modules
- Integration tests exercise the framed path and real multi-request
  batches, use dynamic ports, and assert specific failure output
- Unit tests for the client's `sequence`, `transport`, and `client` modules

### Documentation

- README quick start corrected: default port 2003, real package names, seed
  requirement, and client flag documentation (`-P`, `-s`, `-t`, `-u`, `-r`)
- RELEASE-CHECKLIST package names fixed; publishable crates enumerated
- CONTRIBUTING unsafe-code policy matches reality (keys-crate exceptions in
  `online/aws_lc_ed25519.rs` and `online/sshagent.rs`)
- `MAX_VERSIONS` cap documented as a deliberate deviation from RFC 5.1.1;
  UDP-only transport noted in `doc/RFC-PROTOCOL.md`; `doc/REQUEST-FLOW.md`
  updated to the current response-generation flow
- Dockerfile dependency-cache layer fixed (all workspace manifests, lib/bin
  stubs, no masked build failures) so image rebuilds reuse cached
  dependencies

## [2.0.0] - 2025-10-06

- Initial release of Roughenough 2.0

## Versioning Policy

This project aspirationally follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and tries to 
adhere to it as closely/practically as possible:

- **MAJOR** version increments indicate incompatible API changes
- **MINOR** version increments add functionality in a backward compatible manner
- **PATCH** version increments make backward compatible bug fixes

Given a version number MAJOR.MINOR.PATCH:
- Breaking changes to public APIs or protocol implementation increment MAJOR
- New features that maintain backward compatibility increment MINOR
- Bug fixes and internal improvements increment PATCH


