# Changelog

## [Unreleased]

### Security

- Client: `--set-clock` requires `-k/--pub-key`; keyless queries warn
- Server: refuses to start without `--seed`; all-zero test seed requires
  `--insecure-zero-seed`
- Server: truncated (oversized) datagrams are dropped
- Server: private-use protocol versions (0xc0000000-0xffffffff) are not
  negotiated or answered (RFC 12.2)
- Keys: seed values are never logged
- Reporting server: reports are verified before storage; storage capped,
  submissions rate-limited, request bodies size-limited

### Fixed

- Client: saturating arithmetic applied to MIDP/RADI
- Client: unrepresentable midpoints display as raw values
- Client: receive buffers sized to `MAX_RESPONSE_SIZE`
- Client: bracketed IPv6 literals parse in server lists; UDP datagrams
  only sent to UDP addresses; zero values for `-n`, `-u`, `-r` rejected
- Client: malfeasance reports carry the full measurement chain and use
  `application/roughtime-malfeasance+json`
- Client: duplicated or stale datagrams no longer abort a measurement
- Keys: cloud backends return errors instead of panicking; seed-load
  failures exit the server cleanly
- Keys: `try_choose_backend` returns errors for unavailable backends;
  PKCS#11 backend selectable via `--seed-backend pkcs11`
- Keys: `generate --key seed://...` no longer panics; `store` output is
  usable as a `--seed` value
- Server: `--interface` accepts only IP addresses
- Server: metrics rates computed from per-interval deltas
- Server: `Response::to_wire` bounds check accounts for frame overhead
- Server: non-WouldBlock receive errors are counted and don't busy-spin
- Server: a worker thread dying shuts the server down with an error
- Reporting server: first report entries carrying `rand` are accepted
  (RFC 8.4.1)
- Protocol: `UnexpectedMagic` error shows the correct 'ROUGHTIM' constant

### Changed

- `SeedBackend` requires `Send`; hand-written `unsafe impl Send/Sync` on
  the server's `KeySource` deleted
- CLI `--version` derives from the crate version
- Reporting server: new `--listen <ADDR:PORT>` option (default
  `0.0.0.0:3000`); storage documented as in-memory
- `roughenough-integration-test` and `roughenough-reporting-server` are
  `publish = false`
- Dead code removed: unreachable non-Linux `stub_backend` in Linux KRS

### Performance

- Server: batched sends use one `sendmmsg` syscall on Linux (median batch
  send time down 8-10% at batch sizes 16-64); server crate moves from
  `#![forbid(unsafe_code)]` to `#![deny(unsafe_code)]` with one exception
- Server: per-version response templates persist across batches (~1% at
  batch 64)
- Protocol: `Request` drops the ZZZZ padding array (1064 -> ~110 bytes);
  `PendingRequest` stores only the nonce (batch 64 median 87.0 -> 85.5 us)
- Server: `MerkleTree::reserve` rounds capacity to a power of two;
  receive buffer reused; metrics snapshots allocation-free
- Client: response validation slices signed regions in place, removing
  four heap copies per response

### Simplified

- Protocol: `fixed_tag!` macro generates fixed-size tag boilerplate;
  `SrvCommitment` and `Signature` are `Copy`
- Protocol: `RequestedVersions`/`SupportedVersions` alias one
  `VersionList` type
- Protocol: `DELE_PREFIX`/`SREP_PREFIX` constants replace per-version
  accessors
- Merkle: `root_from_paths` is a free function
- Server: library modules are `#[doc(hidden)]`

### Added

- Fuzzing: `fuzz_response_parse` target; fuzz targets build in CI;
  dependabot covers `fuzz/`
- Adversarial response-parsing tests; tests for untested tag modules
- Integration tests cover the framed path and multi-request batches
- Unit tests for the client's `sequence`, `transport`, and `client` modules

### Documentation

- README quick start corrected (port, package names, seed, client flags)
- RELEASE-CHECKLIST package names fixed; publishable crates enumerated
- CONTRIBUTING unsafe-code policy matches reality
- `MAX_VERSIONS` cap documented as an RFC 5.1.1 deviation; UDP-only
  transport noted; `doc/REQUEST-FLOW.md` updated
- Dockerfile dependency-cache layer fixed

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


