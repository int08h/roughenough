# Changelog

## [Unreleased]

### Breaking

- Server library: `NetworkHandler::send_response` and `NetworkHandler`'s
  `Debug` impl were removed; use `queue_response` + `flush_responses`
- Keys: cargo features `longterm-aws-kms` and
  `longterm-aws-secret-manager` are replaced by `longterm-aws`;
  `longterm-gcp-kms` and `longterm-gcp-secret-manager` are replaced by
  `longterm-gcp`. The implicit `tokio` feature is gone
- Protocol: `Nonce` and `PublicKey` no longer implement the panicking
  `From<&[u8]>`; use `TryFrom<&[u8]>`, which returns
  `Error::WrongTagSize`
- Protocol: `SrvCommitment::try_from` reports `Error::WrongTagSize` (was
  `BufferTooSmall`)
- Protocol: removed `tags::fixed_tag::FixedTag`, `From<&Vec<u8>> for
  Nonce`, and `From<Nonce> for [u8; 32]`
- Protocol: `MerkleRoot` implements `AsRef<[u8]>` instead of
  `AsRef<[u8; 32]>`; use `MerkleRoot::as_array()` for the array
- Protocol: removed unused API: `Tag`'s `Ord`/`PartialOrd`,
  `Tag::is_nested`, `Tag::HASH_PREFIX_SRV` (use
  `SrvCommitment::HASH_PREFIX_SRV`), `Tag::from_wire`, `TryFrom<u32> for
  Tag`, `From<Tag> for u32`, `Error::InvalidTag`, `Error::IoError`,
  `Response::MINIMUM_SIZE` (use `wire::MINIMUM_FRAME_SIZE`),
  `VersionList::is_supported`, `MessageType::Invalid`, `FromStr for
  ProtocolVersion`, and the `ParseCursor` methods `has_remaining`,
  `capacity`, `get_u32`, `try_get_u32`, `try_put_slice`, `reset`, and
  `try_put_u64_le`
- Protocol: an over-long PATH reports `Error::InvalidPathLength` (was
  `BufferTooSmall`)
- Protocol: `FromWireN` is merged into `FromWire`, which now requires
  `from_wire_n(cursor, n)` and provides `from_wire(cursor)`. `from_wire`
  on a fixed-size tag now requires exactly that many remaining bytes
- Protocol, Common: `ClockSource` moved from `roughenough_protocol::util`
  to `roughenough_common::clocksource`; the test-only `now`, `advance`,
  and `decrease` methods were removed
- Client API: `ResponseValidator::validate` takes `(request_bytes,
  response_bytes)` and returns the parsed `Response`, so the checked
  fields always come from the signed bytes
- Client API: `ResponseValidator::new` takes `Option<PublicKey>`;
  `new_with_key` is removed
- Client API: `ResponseValidator::validate_causality` is now
  `CausalityViolation::find`
- Client API: malformed responses surface as
  `ClientError::ValidationFailed(InvalidMessage)` instead of
  `ClientError::BadResponse`
- Client API: `ReportingError` has new variants for report verification
  failures
- Client API: `Measurement::builder` and `MeasurementBuilder` are removed;
  `Measurement`s come only from `Client`
- Client API: `ReportingError::SerializationError` is removed
- Client: `MalfeasanceReport::submit` and the `--report` flag exist only
  with the `reporting` feature
- Client: `--report` fails before any query when the server list has no
  `reports` URL
- Reporting server: `validate_report` and its `validation` module are
  removed; use `MalfeasanceReport::verify()`
- Client API: `ClientTransport::send`/`recv` no longer take or return a
  `SocketAddr`
- Client API: `UdpTransport::new` returns `io::Result`, and
  `ClientBuilder::build` returns `Result<Client, ClientError>`
- Client: the UDP socket is connected, so datagrams from other sources
  are ignored, and a closed port fails fast with "Connection refused"
  instead of waiting for the timeout
- Client API: `server_list` types are deserialize-only; `ServerList::new`,
  `add_server`, `to_json`, `Server::new`, and `Address::new` are removed
- Client API: removed the unused server-list accessors `Server::addresses`,
  `first_address`, `version`, and `public_key_type`, and
  `Address::protocol`; `ServerList::validate` and `Server::validate` are
  private, and `Address::validate` is removed
- Client API: `ServerList::choose_random` returns `Vec<&Server>`
- Client API: an invalid server-list address is reported as
  `server_list::Error::InvalidJson`
- Client: a hostname/port and `-l` are mutually exclusive at parse time;
  giving both or neither exits 2 (was 255)
- Client: `-k` and `-n` are rejected with `-l`
- Client: `--report` requires `-l`
- Client: `-s` does not set the clock when causality violations are
  found; it exits 1 instead
- Client: causality violation output follows `--zulu`, `--epoch`, and `-f`
- Client API: the `roughenough_client::args` module is removed
- Client: a response whose VERS does not contain its VER is rejected
  with the new `ValidationError::VerNotInVers` (RFC 5.2.5).
  `ResponseValidator::validate` does not perform this check; call
  `check_vers_contains_ver` to apply it elsewhere
- Keys: `Seed::new(&[u8])` and `Seed::len()` are removed; use
  `Seed::try_from(&[u8])` or `Seed::from_bytes(&[u8; 32])`.
  `Seed::expose()` returns `&[u8; 32]`. `MemoryBackend::from_value` takes
  `&[u8; 32]`. Common: `encoding::try_decode` returns
  `Zeroizing<Vec<u8>>` and accepts mixed-case hex
- Keys: `storage::try_load_seed` and `storage::try_store_seed` are
  synchronous; `storage::try_load_seed_sync` and the `runtime` module are
  removed; `Protection::from_prefix` is replaced by `Protection::split`
- Server library: the hidden `seed_file` module moved to
  `roughenough_keys::seed_file`. Keys: `StorageError` has a new
  `SeedFile` variant for seed-file I/O and validation errors

### Security

- Keys, Common: decode buffers for seed values are zeroized, including
  failed decoding attempts
- Keys: the KMS data-encryption key is zeroized after use

### Fixed

- Keys: `roughenough_keys open` exits non-zero instead of printing a
  random seed when no enabled KMS backend matches the envelope key id or
  `--key` lacks a scheme prefix
- Server: `--seed-backend pkcs11` works; it no longer requires
  `--seed-file` (and rejects it), since the token holds the long-term
  key. Keys: the PKCS#11 backend reads the public key once at startup
  and reports token errors instead of panicking
- Server: worker metrics are no longer lost when the metrics channel is
  full, and `total_requests` (JSON and log) now includes requests dropped
  for an SRV mismatch or no common version
- Merkle: `compute_root` no longer appends padding to the stored leaves,
  so adding leaves after computing a root yields the correct tree
- Client: `--timeout` is honored when querying a single server (it was
  fixed at 2 seconds)
- Client: `--timeout 0` is rejected instead of panicking
- Client: a late or duplicated response to an earlier request is skipped
  instead of failing the query (affects `-n N`)
- Client: a response whose VERS lists no supported version is rejected
  with `NoSupportedVersions` (RFC 5.2.5)
- Client: `--zulu` prints the time zone as UTC instead of a literal `%Z`

### Added

- Server: new features `online-ssh-agent`, `longterm-aws`, `longterm-gcp`,
  and `release`; release binaries and the Docker image are built with
  `--features release` instead of `--all-features`, so they no longer
  include test hooks
- Protocol: `FromFrame::from_frame_bytes` parses a framed Request or
  Response from a shared byte slice
- Client: `test-utils` feature exposing shared test fixtures
  (`roughenough_client::test_utils`) for other crates' tests
- Protocol: all fixed-size tags gain `as_array()`
- Common: `crypto::verify_with_context` verifies an Ed25519 signature over
  a context prefix and message
- Client: `MalfeasanceReport::verify()` validates a received report
- Client: `-s` works with `-l` without `-k`, since the server list
  supplies the public keys
- Keys: `storage::decode_seed` decodes a hex or base64 seed value;
  `Seed::LEN` and `seed::InvalidSeedLength` are new
- Keys: `storage::parse_envelope` decodes a prefixed seed envelope, and
  `storage::load_envelope` recovers the seed an envelope refers to
- Keys: `storage::load_seed_file` reads and validates a seed file, then
  loads the seed it describes

## [2.2.0] - 2026-10-11

### Breaking

- Docker: the runtime image runs as the distroless `nonroot` user (uid
  65532) instead of root. Mounted seed files must be owned by uid 65532,
  or the server cannot read them and refuses to start.
- Server: `--num-threads 0` and `--rotation-interval 0` are rejected, and
  `--metrics-interval` must be 1 to 86400 seconds. Configurations that
  set these values no longer start.

### Security

- Server: the listening socket no longer sets `SO_REUSEADDR`, which on
  Linux let any local user bind the Roughtime port and capture traffic;
  `SO_REUSEPORT` alone balances load across workers and is UID-checked
- Server (Linux): a classic BPF socket filter drops runts, oversized
  datagrams, and datagrams without the ROUGHTIM magic in the kernel, so
  floods of them cannot fill worker receive buffers (`doc/BPF-FILTER.md`)
- Docker: the runtime image no longer runs as root (see Breaking)

### Fixed

- Server: a backward wall-clock step no longer stalls metrics reporting
  until the clock catches up
- Server: workers rotate the online key when the clock leaves its
  delegation span. A backward step no longer leaves responses with MIDP
  before MINT, which clients reject, and a forward jump no longer
  triggers one rotation per skipped interval.
- Server: workers no longer generate a second online key at startup,
  halving startup long-term-key signatures (HSM or KMS calls)

### Added

- Protocol: `VersionList::push_back`

## [2.1.0] - 2026-10-06

### Breaking: RFC 10049

Roughtime is now published as RFC 10049. This release follows the RFC.

- Protocol: version 1 (0x00000001) signatures use the RFC 10049 context
  strings, `"Roughtime v1 response signature"` and
  `"Roughtime v1 delegation signature"` (RFC 5.2.1, 5.2.6)
- Protocol: the recognized versions are version 1 and draft 0x8000000c.
  Other values in the experimental range (0x80000000-0xbfffffff) are
  unknown and are ignored in VER lists. Draft 0x8000000c keeps the
  `"RoughTime v1 ..."` context strings.
- Server: answers only version 1 and advertises only version 1 in VERS.
  Requests that do not offer version 1, including requests from 2.0.0
  clients, are ignored (RFC 5.1.1).
- Server: default port is 5319, assigned by IANA (RFC 12.1). It was 2003.
  Use `--port` or `ROUGHENOUGH_PORT` to keep the old port. The Dockerfile
  exposes 5319.
- Client: offers version 1 by default. `-P/--protocol` takes `1` (default),
  `both` (version 1 and draft 0x8000000c), or `19` (draft 0x8000000c
  only). It no longer takes `14` or `0`.
- Client: a response whose VER was not offered in the request is rejected
  (RFC 7), with the new `ValidationError::UnofferedVersion`
- Client: the server-list `version` field is a `ServerVersion`. Integers
  (RFC 8.3) and older string values such as `"IETF-Roughtime"` are both
  accepted. `Server::new` and `Server::version` use the new type.
- Reporting server: accepts reports with version 1 and draft 0x8000000c
  responses
- Protocol API (`roughenough-protocol`): versions are a `ProtocolVersion`
  struct with `RFC` and `DRAFT` constants; `dele_prefix()` and
  `srep_prefix()` return the context strings for a version. This release
  changes public API without a major version bump.

### Breaking: other

- Server: the long-term seed is read from a file given by `--seed-file`
  or `ROUGHENOUGH_SEED_FILE`. `--seed` and `ROUGHENOUGH_SEED` are removed.
  The file must be a regular file, not a symlink, with no group or other
  permissions, and at most 64 KiB.
- Keys: AWS KMS and GCP KMS seed envelopes use AES-256-GCM with a random
  nonce instead of AES-256-GCM-SIV. Envelopes sealed by 2.0.0 do not open
  in 2.1.0; re-seal the seed with `roughenough_keys store`.
- Client API: `Measurement::midpoint_datetime` returns `jiff::Timestamp`
  instead of `chrono::DateTime<Utc>`
- Merkle API: `root_from_paths` is a free function that returns
  `Option<Hash>`, and `None` when INDX bits remain after PATH is consumed
- Docker: the runtime image is `gcr.io/distroless/cc-debian13`, which has
  no shell (it was `cc-debian12:debug`). The builder is Rust 1.94 on
  Debian trixie and uses the `release-lto` profile.

### Security

- Client: `--set-clock` requires `-k/--pub-key`; keyless queries warn
- Server: refuses to start without `--seed-file`; all-zero test seed
  requires `--insecure-zero-seed`
- Server: truncated (oversized) datagrams are dropped
- Server: private-use protocol versions (0xc0000000-0xffffffff) are not
  negotiated or answered (RFC 12.2)
- Server: requests whose SRV does not match the server's long-term key
  are dropped (RFC 5.1)
- Keys: seed values are never logged; transient seed buffers are zeroized
- Keys: `roughenough_keys` creates output files with mode 0600
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
- Client: queries to IPv6 servers bind an IPv6 socket (#97)
- Protocol: unknown tags in requests and responses are ignored (RFC 5.1,
  RFC 7)
- Keys: cloud backends return errors instead of panicking; seed-load
  failures exit the server cleanly
- Keys: `try_choose_backend` returns errors for unavailable backends;
  PKCS#11 backend selectable via `--seed-backend pkcs11`
- Keys: `generate --key seed://...` no longer panics; `store` output is
  usable as seed-file contents
- Server: `--interface` accepts only IP addresses
- Server: requests from 1024 to 1472 bytes are accepted. RFC 5.1 sets
  only a minimum; 2.0.0 required exactly 1024 bytes.
- Server: SIGTERM shuts the server down cleanly; 2.0.0 handled only
  SIGINT
- Server: workers process at most 8 batches per wakeup before checking
  key rotation, metrics, and shutdown, so sustained load cannot starve
  them
- Server: `--quiet` also limits cloud SDK logging to errors
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
- `roughenough-reporting-server` is a workspace member but not a default
  member; build it with `cargo build -p roughenough-reporting-server`
- Keys: tokio is optional and enabled only by the `longterm-*` cloud
  features
- Dependencies: the default build graph drops from 102 to 49 external
  crates, and the server binary no longer links tokio. chrono is replaced
  by jiff, crossbeam-channel by `std::sync::mpsc`, ctrlc by signal-hook,
  and fastrand by aws-lc-rs randomness.
- Reporting server: report IDs are random 128-bit hex strings instead of
  ULIDs

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
- Keys: online Ed25519 signing does not allocate

### Simplified

- Protocol: `fixed_tag!` macro generates fixed-size tag boilerplate;
  `SrvCommitment` and `Signature` are `Copy`
- Protocol: `RequestedVersions`/`SupportedVersions` alias one
  `VersionList` type
- Server: library modules are `#[doc(hidden)]`

### Added

- Fuzzing: `fuzz_response_parse` target; fuzz targets build in CI;
  dependabot covers `fuzz/`
- Adversarial response-parsing tests; tests for untested tag modules
- Integration tests cover the framed path and multi-request batches
- Unit tests for the client's `sequence`, `transport`, and `client` modules
- Server allocation tests and worker-loop tests
- Common: `secure_shuffle`, a bias-free shuffle using aws-lc-rs randomness
- Release: cargo-dist configuration for Linux x86_64 and aarch64 archives
- Docker: `.dockerignore`
- CI: least-privilege workflow permissions; keys feature-matrix check;
  pre-commit hooks for `cargo fmt` and `cargo clippy`

### Documentation

- References point at `doc/RFC-10049.txt`; the draft text and
  `doc/RFC-PROTOCOL.md` are removed
- README documents protocol versions and the context strings
- README quick start corrected (port, package names, seed, client flags)
- RELEASE-CHECKLIST package names fixed; publishable crates enumerated
- CONTRIBUTING unsafe-code policy matches reality
- `MAX_VERSIONS` cap documented as an RFC 5.1.1 deviation; UDP-only
  transport noted
- New `doc/REQUEST-FLOW.md` describes the request and response flow
- New `AI_POLICY.md` and `AGENTS.md`
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


