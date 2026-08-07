# Remediation Plan

This plan addresses the findings of the 2026-08-07 multi-agent review (RFC
draft-19 conformance, correctness, completeness, simplicity, and performance).
It is written for a developer or agent with no prior context. Work the phases
in order; items within a phase are independent unless noted. Each item states
the problem, the change, the new or changed tests, and acceptance criteria.

Line numbers were accurate at review time (commit 70e8bd8 era) and may drift;
locate code by the named symbols when lines do not match.

## Ground rules (apply to every item)

- ASCII only in code, comments, strings, commits, and docs. No emojis.
- Run `cargo clippy --workspace --all-targets --all-features` and
  `cargo +nightly fmt` before every commit. Clippy is currently clean at zero
  warnings; keep it that way.
- Never ignore or disable a test to make it pass.
- Performance changes (Phase 8 only) require before/after benchmarks with
  percentiles, not averages. Reject changes that do not measure as improvements.
- Comments explain why, not what. Delete stale comments with the code they
  describe.
- Keep comments, commit messages, and PR descriptions succinct, brief, and
  to the point. State what changed and why in as few words as needed; no
  narration, no filler.
- Convert a panic (`unreachable!`, `todo!`, `expect`) to an error return
  only when the path is actually reachable. Verify reachability first; a
  genuinely unreachable arm keeps its `unreachable!`.
- `cargo test --workspace` must pass after each item. The
  `roughenough-reporting-server` socket-binding tests require an environment
  that permits binding listeners; they are not flaky.

## Explicit non-goals

- **No TCP transport.** The client and server are UDP only, by design. Do
  not add a TCP listener, a TCP client transport, or any TCP plumbing; the
  RFC's TCP SHOULDs are declined. (Filtering out `Protocol::Tcp` entries
  from server lists in 1.5 is consistent with this: it stops UDP datagrams
  being sent to TCP addresses.)
- **`VersionList::MAX_VERSIONS` stays at 8.** The RFC allows up to 32 entries
  in VER; this implementation deliberately caps parsing at 8. Do NOT raise it.
  The only action is documentation: add a comment at the `MAX_VERSIONS`
  definition (`crates/roughenough-protocol/src/version_list.rs`) stating this
  is a deliberate deviation from RFC 5.1.1's 32-entry allowance, and why
  (bounded stack usage; version 1 and drafts sort within the first 8 slots in
  practice).

---

# Phase 1: Client safety and correctness (highest priority)

## 1.1 Refuse `--set-clock` without a verified public key

**Problem.** `crates/roughenough-client/src/main.rs` calls
`set_system_clock(midpoint)` whenever `--set-clock` is passed, with no
requirement that `--pub-key` was supplied. When `pub_key` is `None`,
`ResponseValidator::validate` (`crates/roughenough-client/src/validation.rs`,
`check_dele_signature` gate near line 112) skips the long-term key check, and
the SREP signature is verified against the PUBK carried inside the response's
own CERT -- a self-signed chain. Any attacker who can land a UDP datagram on
the client's ephemeral port can set the system clock. The client socket is
unconnected and the response source address is discarded, so nothing narrows
who may answer.

**Change.**
1. In `crates/roughenough-client/src/args.rs`, add `requires = "pub_key"` to
   the `set_clock` clap attribute so `--set-clock` without `-k` is rejected at
   argument parsing with a clear clap error.
2. In `main.rs`, when a single-server query runs without `pub_key`, print a
   prominent warning to stderr (once, not per response):
   `WARNING: no public key provided (-k); responses are NOT authenticated`.
   Do not warn in quiet mode is NOT acceptable here -- warn even with `-q`,
   since `-q` suppresses "messages except for errors" and this is
   security-relevant.
3. In `crates/roughenough-client/src/validation.rs`, when `pub_key` is `None`,
   ensure the returned/printed validation status cannot read as "validated".
   The library doc comment near `client.rs:18` already says "not recommended";
   extend it to state exactly what is and is not checked without a key.

**Tests (new).**
- `args.rs` unit test: `Args::try_parse_from(["prog", "host", "2003", "-s"])`
  returns an error; adding `-k <key>` parses successfully.
- Integration test (`crates/roughenough-integration`): client run with
  `--set-clock` and no `-k` exits nonzero with the clap error on stderr.
  Assert on the specific error text, not merely nonzero exit.

**Acceptance.** `--set-clock` is impossible without `-k`. Unauthenticated
queries print the warning exactly once.

## 1.2 Saturating arithmetic on MIDP/RADI

**Problem.** Three sites compute `midpoint - radius as u64` and
`midpoint + radius as u64` on values taken straight from a (possibly hostile
or buggy) server: `validation.rs` (`CausalityViolation::new`, ~lines 51-52),
`validation.rs` (`validate_causality`, ~lines 254-255), and `main.rs`
(`display_violation`, ~lines 232-233). MIDP is a `u64` and RADI a `u32`,
bounded only by the same server's signed MINT/MAXT. MIDP < RADI underflows:
debug builds panic, release builds wrap to ~1.8e19 and then every pairwise
comparison flags a spurious causality violation -- which, with `--report`,
submits a false malfeasance report naming an honest server.

**Change.** Replace all six expressions with `saturating_sub` /
`saturating_add`. Introduce two helpers on `Measurement`
(`crates/roughenough-client/src/measurement.rs`):

```rust
pub fn lower_bound(&self) -> u64 { self.midpoint().saturating_sub(self.radius() as u64) }
pub fn upper_bound(&self) -> u64 { self.midpoint().saturating_add(self.radius() as u64) }
```

and use them everywhere bounds are computed, so the arithmetic exists in one
place. Remove the `assert!` form in `CausalityViolation::new` if present;
constructors must not assert on wire-derived values.

**Tests (new).** In `validation.rs` tests:
- Measurement with `midpoint = 10`, `radius = 100`: `lower_bound()` is 0, no
  panic in debug, and `validate_causality` does NOT report a violation against
  a normal second measurement (this is the false-report regression test).
- Measurement with `midpoint = u64::MAX - 1`, `radius = 100`:
  `upper_bound()` is `u64::MAX`, no overflow.
- Existing causality-violation tests still pass (real violations still
  detected).

**Acceptance.** No unchecked add/sub on MIDP/RADI anywhere in the client
(grep for `midpoint() -` and `midpoint() +` returns nothing outside the two
helpers). Debug-build test run with the hostile values does not panic.

## 1.3 Remove `Timestamp::from_second(...).unwrap()` panics

**Problem.** `measurement.rs` (`midpoint_datetime`, ~line 147) and `main.rs`
(`display_measurement` ~line 277, `display_violation` ~lines 235-238) call
`jiff::Timestamp::from_second(midpoint as i64).unwrap()`. jiff (pinned 0.2.x)
returns `Err` outside roughly -377705023201..=253402207200 (year 9999). A
signed response with MIDP above that range -- which passes validation because
MINT/MAXT come from the same server -- crashes the client. In unauthenticated
mode (no `-k`) any injected datagram can do it.

**Change.**
1. Change `Measurement::midpoint_datetime` to return
   `Option<jiff::Timestamp>` (or `Result`); it is a workspace-internal API.
2. At display sites, fall back to printing the raw value when conversion
   fails, e.g. `"<unrepresentable midpoint: 300000000000 sec>"`, and continue.
   Display code must never panic on wire-derived values.
3. Audit the client crate for other `unwrap()`/`expect()` on values derived
   from a response (`rg 'unwrap\(\)|expect\(' crates/roughenough-client/src`)
   and convert any that are reachable from wire data.

**Tests (new).**
- `measurement.rs`: `midpoint_datetime` with `midpoint = 300_000_000_000`
  returns `None` (no panic); with a sane value returns `Some`.
- A display-path test (extract the formatting into a testable function if
  needed) that formats a measurement with an unrepresentable midpoint and
  asserts the fallback string.

**Acceptance.** `rg 'from_second' crates/roughenough-client` shows no
`unwrap`/`expect` on the result.

## 1.4 Client receive buffer below RFC maximum response size

**Problem.** `crates/roughenough-client/src/client.rs` (~line 318) receives
into `[0u8; 1024]`. A conforming response can carry a 32-element PATH
(~1440 bytes framed). `recv_from` silently truncates, and the subsequent parse
fails with a misleading error.

**Change.** Define a shared constant in `roughenough-protocol` (e.g.
`pub const MAX_RESPONSE_SIZE: usize = 1500;` next to `MAX_REQUEST_SIZE`, with
a comment deriving it from the RFC maximum: fixed response overhead plus
32 * 32 bytes of PATH, rounded up to a typical MTU). Use it for the receive
buffer in `client.rs` and in `sequence.rs` (~line 85), which has the same
buffer.

**Tests (new).** Protocol-crate test: construct a `Response` with a
32-element PATH, serialize with `to_frame`, assert its size fits in
`MAX_RESPONSE_SIZE` and that `Response::from_frame` round-trips it.

**Acceptance.** No 1024-byte receive buffers remain in the client crate.

## 1.5 Server list: IPv6 and transport filtering

**Problem.** `crates/roughenough-client/src/server_list.rs`
(address validation, ~lines 270-285) splits on `':'` with `splitn(2, ':')`,
rejecting bracketed IPv6 literals like `[2001:db8::1]:2003`; one such entry
makes the whole JSON file unloadable because every entry is validated at load.
Separately, `main.rs` (~lines 184-185) uses `server.first_address()` without
filtering on `Protocol`, so a server whose first address is TCP gets UDP
datagrams sent to its TCP port.

**Change.**
1. Replace the manual split/parse with `str::parse::<std::net::SocketAddr>`,
   which handles `host:port` and `[v6]:port`. For hostname (non-IP) entries,
   split on the LAST colon (`rsplit_once(':')`) so IPv6 is not misparsed, and
   validate the port half as `u16`. Update `Address::host()`/`port()`
  (~lines 288-300) to the same rule so they cannot panic on IPv6.
2. Add a `udp_addresses()` (or `first_udp_address()`) accessor that filters
   `Protocol::Udp`, and use it in `main.rs`. A server with no UDP address is
   skipped with a log line, not queried over the wrong transport.

**Tests (new).** In `server_list.rs`:
- Parse a JSON list containing `[2001:db8::1]:2003` -> loads, `host()` and
  `port()` return the literal and 2003.
- Entry with only a TCP address: `first_udp_address()` returns `None`.
- Mixed entry (TCP first, UDP second): UDP address is selected.
- Regression: existing IPv4 and hostname entries still parse.

**Acceptance.** An IPv6 entry no longer poisons the file; no UDP datagram is
ever addressed to a `Protocol::Tcp` address.

## 1.6 Reject zero-count CLI arguments

**Problem.** `num_requests = 0` leaves midpoint at 0 and produces confusing
output (`main.rs` ~lines 69-81); `num_measurement_rounds = 0` panics at
`measurements.last().unwrap()` (`main.rs` ~line 125).

**Change.** In `args.rs`, constrain with clap:
`value_parser = clap::value_parser!(u32).range(1..)` (adjust types as needed)
on `num_requests`, `num_unique_servers`, and `num_measurement_rounds`.

**Tests (new).** `Args::try_parse_from` with `-n 0` and with `-r 0` each
return an error; `-n 1` parses.

**Acceptance.** No zero value reaches `main`'s logic.

---

# Phase 2: Keys crate robustness

## 2.1 Cloud backends must return `Result`, never panic

**Problem.** All four cloud backends panic on any API failure, so a server
started with the documented production configuration (`--seed aws-kms://...`)
aborts with a stack trace on any transient credential, permission, or network
error. Roughly 20 `unwrap`/`expect`/`assert` sites:
- `crates/roughenough-keys/src/longterm/gcpkms.rs`: `encrypt_seed` returns
  `SeedEnvelope` (not `Result`); panics ~lines 48, 60; bare CRC
  `assert_eq!` ~line 63.
- `crates/roughenough-keys/src/longterm/awskms.rs`: same shape; panics
  ~lines 41, 60, 70, 92, 102.
- `crates/roughenough-keys/src/longterm/gcpsecret.rs`: `get_seed` returns
  `Seed`; panics ~lines 22, 29, 31, 52.
- `crates/roughenough-keys/src/longterm/awssecret.rs`: `get_seed` returns
  `Seed`; panics ~lines 31, 33, 40.
The TODO at `crates/roughenough-keys/src/storage.rs:334` marks one call site
of this pattern.

**Change.**
1. Change every public operation on the four backends to return
   `Result<_, StorageError>`. Add variants to `StorageError` as needed, e.g.
   `CloudBackend { backend: &'static str, detail: String }` (or per-service
   variants if that matches the existing enum style -- inspect
   `crates/roughenough-keys/src/storage.rs` first and follow it). Preserve the
   underlying SDK error text in `detail`.
2. Replace the CRC `assert_eq!` in gcpkms with an
   `Err(StorageError::...IntegrityCheckFailed...)` return.
3. Propagate through `try_load_seed`/`try_store_seed` in `storage.rs` with
   `?`, deleting the TODO at ~line 334.
4. In the server boot path, a seed-load failure must surface as a clean
   `error!` log plus nonzero exit, not a panic backtrace. Check
   `crates/roughenough-server/src/main.rs` where the seed is loaded and map
   the error accordingly.

**Tests (new).** Cloud calls cannot run in CI without credentials, so test
the seams:
- Unit tests for each new `StorageError` variant's `Display` output.
- For each backend, factor response decoding/validation (base64/hex decode,
  CRC check, envelope shape) into pure functions and unit-test them with bad
  input, asserting `Err`, not panic. The gcpkms CRC mismatch case must have a
  test.
- Keep the existing `#[ignore]`d credentialed tests; update their assertions
  to the new `Result` signatures.

**Acceptance.** `rg 'unwrap\(\)|expect\(|assert' crates/roughenough-keys/src/longterm/`
shows no panicking call on a fallible cloud operation. A deliberately bad
`--seed aws-kms://nonexistent` exits with an error message, not a backtrace
(manually verified once; document the observed message in the PR).

## 2.2 `try_choose_backend`: no panics, wire up PKCS#11

**Problem.** `crates/roughenough-keys/src/seed.rs` (~lines 96-125):
`"tpm" => todo!()`, `"yubikey" => todo!()`, and a catch-all
`_ => unreachable!("invalid backend: {}", backend)` -- all panics in a `pub`
library function that returns `Result<_, BackendError>`. Meanwhile the
`online-pkcs11` feature compiles, is advertised in README (~line 97) and the
release checklist, and is CI-checked, but has NO arm here and no CLI value in
`SeedBackendArg` (`crates/roughenough-server/src/args.rs` ~lines 113-121), so
it is unreachable at runtime.

**Change.**
1. Replace `todo!()` and `unreachable!()` with
   `Err(BackendError::BackendNotAvailable(...))` (reuse the existing variant
   style; a `NotSupported` variant already exists per review -- verify and use
   whichever fits). These arms ARE reachable -- this is a `pub` function
   taking an arbitrary `&str` -- so the ground rule's reachability test is
   met; do not extend this conversion to arms that genuinely cannot be
   reached.
2. Add a `"pkcs11"` arm, gated `#[cfg(feature = "online-pkcs11")]`,
   constructing the PKCS#11 backend from
   `crates/roughenough-keys/src/online/pkcs11.rs`. When the feature is off,
   the arm returns `BackendNotAvailable` like the Linux-KRS non-Linux path
   (~lines 104-108) does.
3. Add `Pkcs11` to `SeedBackendArg` in the server's `args.rs`, feature-gated
   the same way the crate wires other optional backends (inspect how `krs` is
   gated and mirror it). Document required configuration (module path, slot,
   PIN env var) in the arg help text based on what `pkcs11.rs` needs.

**Tests (new).** In `seed.rs`:
- `try_choose_backend("tpm")`, `("yubikey")`, `("garbage")` all return `Err`,
  never panic (this test would have caught the original bug).
- `try_choose_backend("pkcs11")` with feature off returns
  `BackendNotAvailable`; with feature on (add to the CI keys feature matrix,
  `.github/workflows/rust.yml` ~lines 108-132) it proceeds past selection
  (construction may still fail without a token; assert the error is NOT
  `BackendNotAvailable`).

**Acceptance.** No `todo!`/`unreachable!` in `seed.rs`. PKCS#11 is selectable
end to end or, if that proves too large, the advertisement is removed from
README and RELEASE-CHECKLIST in the same PR (pick one; do not leave the
mismatch).

## 2.3 Storage dispatch: fix `unreachable!`, stop logging the seed

**Problem.**
1. `crates/roughenough-keys/src/storage.rs` (~line 125): `try_store_seed`
   routes the `seed://` prefix to `Protection::Plain`, whose `try_store` arm
   is `unreachable!()` -- so `roughenough_keys generate --key seed://...`
   panics despite the function returning `Result`.
2. `storage.rs` (~line 33): `trace!("Loading seed from {}", encoded_value)`
   logs the plaintext seed when the scheme is `seed://`. The server maps
   `-vv` to TRACE (`crates/roughenough-server/src/main.rs` ~line 193), so
   `roughenough_server -vv --seed <hex>` writes the long-term secret to logs.
3. The module has zero tests despite being the dispatch point for the
   server's identity.

**Change.**
1. Replace the `unreachable!` with an error return (e.g.
   `StorageError::NotImplemented` or a clearer
   `PlainSeedsAreNotStored`-style variant): storing a plaintext seed is a
   no-op by design -- say so in the error message. This arm is reachable
   (the CLI drives it via `--key seed://...`), which is why it converts;
   per the ground rule, leave genuinely unreachable arms alone.
2. Change the trace line to log only the protection scheme (already logged at
   ~line 37) and the value's length, never the value. Audit the whole keys
   crate for other log statements interpolating seed or key material
   (`rg 'trace!|debug!|info!' crates/roughenough-keys/src` and inspect each).
3. Fix `roughenough_keys store` output (`crates/roughenough-keys/bin/keys.rs`
   ~lines 213-220): emit the prefixed single-line form
   (`aws-secret://...`, `gcp-secret://...`, etc.) that `try_load_seed`
   accepts, so the output can be pasted directly into `--seed`. Keep the
   pretty JSON behind a `--json` flag if human inspection is worth
   preserving.

**Tests (new).** New `mod tests` in `storage.rs`:
- `Protection::from_prefix` routing for every scheme string, including
  unknown prefixes -> `Err`.
- `try_store_seed("seed://...")` returns `Err`, does not panic.
- Feature-gated-out schemes return `NotImplemented` (compile the test under
  `--no-default-features`; the CI matrix already runs that combination).
- `store` subcommand output round-trip: generated output string feeds back
  into the load dispatch and selects the correct `Protection` variant.

**Acceptance.** Zero panics reachable from the keys CLI with any `--key` /
`--seed` string. `rg 'encoded_value' crates/roughenough-keys/src/storage.rs`
shows it is never logged.

## 2.4 `SeedBackend: Send`, delete the unsafe impls

**Problem.** `crates/roughenough-server/src/keysource.rs` (~lines 24-28) has
hand-written `unsafe impl Send for KeySource {}` and
`unsafe impl Sync for KeySource {}` plus
`#[allow(clippy::arc_with_non_send_sync)]`, asserting thread-safety for every
present and future `Box<dyn SeedBackend>` with no compiler check. Review
confirmed current backends are in fact `Send` (cryptoki's `Session` carries
its own `unsafe impl Send`; the KRS `mpsc::Sender` is `Send`), so this is
sound today but unchecked.

**Change.** Add `Send` as a supertrait:
`pub trait SeedBackend: Send { ... }` in
`crates/roughenough-keys/src/seed.rs`. Delete both `unsafe impl` lines and
the clippy allow. The compiler now derives `Send`/`Sync` for `KeySource`
(via `Arc<Mutex<_>>`) and every backend must prove itself.

**Tests (new).** Compile-time assertion in `keysource.rs` tests:

```rust
fn assert_send_sync<T: Send + Sync>() {}
#[test]
fn keysource_is_send_sync() { assert_send_sync::<KeySource>(); }
```

Build the full keys feature matrix locally
(`cargo check -p roughenough-keys --features <each>`) to confirm every
backend satisfies the new bound; CI's matrix will enforce it thereafter.

**Acceptance.** `rg 'unsafe' crates/roughenough-server/src` returns nothing.

---

# Phase 3: Server operational safety and correctness

## 3.1 All-zero seed requires explicit opt-in

**Problem.** `--seed` defaults to `""`
(`crates/roughenough-server/src/args.rs` ~line 80) and
`crates/roughenough-server/src/main.rs` (~lines 90-92) responds by running
with an all-zero seed behind a single `warn!`. A bare `roughenough_server`
invocation is a time authority whose long-term identity is a publicly known
constant.

**Change.**
1. Add a flag `--insecure-zero-seed` (default false) to `args.rs` with help
   text stating it is for testing only.
2. In `main.rs`: empty `--seed` without the flag -> log
   `error!("no seed provided; pass --seed or --insecure-zero-seed for testing")`
   and exit nonzero. Empty seed WITH the flag -> current zero-seed behavior,
   warning retained.
3. Update the integration harness and any docs/scripts that rely on the old
   default (`crates/roughenough-integration` starts servers -- search for how
   it passes the seed and add the flag or an explicit test seed;
   `rg 'roughenough_server' crates/roughenough-integration Dockerfile README.md`).

**Tests (new).**
- `args.rs` test: default args parse with `insecure_zero_seed == false`.
- Integration test: server started with neither `--seed` nor the flag exits
  nonzero quickly with the error text; with `--insecure-zero-seed` it serves
  (reuse existing harness startup checks).

**Acceptance.** A no-argument server start refuses to run.

## 3.2 `--interface` parses what its help text promises

**Problem.** `args.rs` (~lines 21-27) documents "IP address or interface
name", but `udp_socket_addr` (~lines 131-138) only does
`str::parse::<IpAddr>()` and panics via `expect` with the same misleading
message. `--interface eth0` -> panic.

**Change.** Pick ONE (recommend the first: smaller, honest):
- (a) Fix the help text to "IP address to listen on" and convert the `expect`
  into a proper error: validate in clap with a `value_parser` that parses
  `IpAddr`, so bad input is a clap error at startup, not a panic.
- (b) Actually implement interface-name resolution (via `if_addrs` or
  similar). Only choose this if a maintainer asks for it; it adds a
  dependency.

**Tests (new).** `args.rs` tests (module currently has none): valid v4 and
v6 addresses parse; `"eth0"` and `"not-an-ip"` produce a clap error (assert
via `Args::try_parse_from`); `rotation_interval` hours-to-seconds conversion
is correct at 1 and at the max accepted value.

**Acceptance.** No `expect`/`unwrap` in `udp_socket_addr`; help text matches
behavior.

## 3.3 Metrics rates: divide deltas, not cumulative totals

**Problem.** `crates/roughenough-server/src/metrics/aggregator.rs`
(~lines 85-93) accumulates worker deltas into `aggregated_metrics` forever
and passes one reporting interval as `elapsed_secs`;
`metrics/snapshot.rs` (~lines 102-106) divides the cumulative totals by that
single interval. Reported responses_per_second and mbytes_per_second inflate
linearly with uptime (10x after ten intervals) in both the log line and the
JSON snapshot files.

**Change.** Keep cumulative totals (useful for the snapshot), but compute
rates from per-interval deltas: retain a `previous` copy of the aggregated
counters, subtract to get the interval delta, divide the delta by
`elapsed_secs`, then update `previous`. Report both cumulative counts and
interval rates in the snapshot so the JSON remains monotonic where consumers
expect it.

**Tests (new).** Aggregator unit test: feed two intervals of synthetic worker
snapshots (e.g. 100 responses each interval, interval = 10 s) and assert the
reported rate is 10/s after BOTH intervals, not 10/s then 20/s. Assert
cumulative totals still sum to 200.

**Acceptance.** Rate output is constant under constant load regardless of
uptime.

## 3.4 Drop truncated datagrams instead of answering them

**Problem.** `crates/roughenough-server/src/network.rs` (~line 37) receives
into `[0u8; MAX_REQUEST_SIZE]` (1472). `recv_from` silently discards the
excess of a larger datagram and returns 1472. The truncated bytes flow to
`add_request` (`requests.rs` ~line 62) and are hashed as the Merkle leaf
(`responses.rs` ~line 93). RFC 5.3 defines the leaf as the full request
packet, so the client -- hashing what it actually sent -- computes a
different leaf, fails the proof, and sees the signature of server
malfeasance. (When the declared frame length itself exceeds the buffer the
parse fails and the request is dropped, which is fine; the bad case is a
valid <=1472-byte frame followed by padding bytes in the same datagram.)

**Change.** Size the receive buffer `MAX_REQUEST_SIZE + 1` (1473). After
`recv_from` returns `n`, if `n > MAX_REQUEST_SIZE`, count it in the existing
oversized/dropped metric and skip the packet entirely (no response, matching
the RFC posture of ignoring invalid requests). Only `n <= MAX_REQUEST_SIZE`
proceeds to parsing.

**Tests (new).**
- `tests/network_resilience_tests.rs` (or the adversarial request tests):
  send a datagram of 1473 and one of 2024 bytes whose first 1024 bytes are a
  valid framed request; assert no response is sent and the drop metric
  increments.
- Regression: a datagram of exactly 1472 bytes containing a valid request is
  still answered.

**Acceptance.** The server never computes a Merkle leaf over bytes that
differ from the datagram the client sent.

## 3.5 Fix `Response::to_wire` bounds check

**Problem.** `crates/roughenough-protocol/src/response.rs` (~line 219) guards
with `cursor.capacity() < self.wire_size()`, but `capacity()` is the whole
buffer while `to_frame` has already written 12 bytes of framing. A response
whose `wire_size()` lands within 12 bytes of the buffer end passes the guard
and panics on an out-of-bounds slice inside the inner writes (reproduced at
review with a 19-element PATH + 2-entry VERS = 1016 bytes into a 1024-byte
buffer). Not reachable today only because `batch_size` is a `u8` capping PATH
depth; `responses.rs` (~line 169) wraps serialization in
`.expect("to_frame(ParseCursor) should be infallible")`.

**Change.**
1. Change the guard to use remaining space: `cursor.remaining()` if
   `ParseCursor` has it (check `crates/roughenough-protocol/src/cursor.rs`),
   otherwise add such a method (`capacity() - position()`), and compare
   against `wire_size()`.
2. Audit the sibling `to_wire` impls (`request.rs` and any others doing the
   same capacity check -- `rg 'capacity\(\)' crates/roughenough-protocol/src`)
   and fix identically.
3. In `crates/roughenough-server/src/responses.rs`, add a compile-time
   assertion documenting the invariant the `.expect` relies on, e.g.
   `const _: () = assert!(RESPONSE_BUF_SIZE >= <max wire size for depth 8>);`
   with a comment deriving the max response size from the batch-size cap.

**Tests (new).** In `response.rs`: build the review's reproduction (PATH
depth and VERS count such that `wire_size()` is within 12 bytes of the
buffer) and assert `to_frame` returns `Err(BufferTooSmall)` -- no panic.
Sweep `wire_size()` values across the boundary (buffer-12 .. buffer) in a
loop asserting error-not-panic for each.

**Acceptance.** The reproduction case returns an error; fuzz targets
(Phase 6.1) exercise serialization round-trips without panics.

## 3.6 Non-WouldBlock receive errors must not busy-spin

**Problem.** `network.rs` (~lines 48-51) returns `MoreData` for any receive
error other than `WouldBlock`, and the worker loop
(`crates/roughenough-server/src/worker.rs` ~lines 93-105) keeps
`still_readable` true, re-entering `collect_requests` without polling. A
persistent socket error would pin a worker at 100% CPU. (Review could not
name a persistent error for an unconnected UDP socket, so this is hardening,
not a live bug.)

**Change.** On a non-WouldBlock error: increment an error counter in the
network metrics -- do NOT log; a persistent error would spam the logs --
and return the variant that sends the loop back to `poll` (whatever
`collect_requests` returns for WouldBlock -- inspect the enum). Losing one
wakeup on a transient error is harmless; spinning is not. The counter
surfaces the condition through the existing metrics reporting.

**Tests (new).** Unit-test the error branch: if the socket is behind a trait
or the function can take a receive result, inject `ErrorKind::Other` and
assert the returned control-flow variant equals the WouldBlock variant and
the counter incremented (and nothing was logged). If injection requires restructuring beyond a small
seam, document the manual reasoning in the PR instead of forcing a mock.

**Acceptance.** No code path re-enters the receive loop unconditionally on
error.

## 3.7 Worker death is loud

**Problem.** `crates/roughenough-server/src/main.rs` (~lines 82-84) joins
workers in order; a panicked worker leaves the process serving at reduced
capacity with no alert, and the aggregator reports zeros for that worker id
indefinitely.

**Change.** Detect a finished/panicked worker and treat it as fatal: simplest
is to have each worker thread hold a guard object whose `Drop` (running on
panic unwind) signals the main thread (e.g. a channel send or an
`Arc<AtomicBool>`), and have the main loop (or the metrics aggregator tick)
check it and initiate shutdown with a clear `error!` naming the worker.
Alternative: spawn with `std::thread::Builder`, park the main thread on a
channel that workers signal on exit, and exit nonzero when any worker exits
before shutdown was requested.

**Tests (new).** Worker-loop test (extend
`crates/roughenough-server/tests/worker_loop_tests.rs`): induce a panic in a
worker (test-only injection point or a test-utils hook) and assert the
process-level signal fires within one metrics interval.

**Acceptance.** Killing one worker thread does not leave a silently degraded
server.

---

# Phase 4: Malfeasance reporting pipeline

Read RFC draft-19 section 8.4 before starting this phase. The client-side
chain construction and the server-side validation must agree; land 4.1 and
4.2 together and integration-test them against each other.

## 4.1 Client: report the full contiguous response chain

**Problem.** `crates/roughenough-client/src/reporting.rs` (~lines 95-104)
builds a report from exactly two measurements (`violation.measurement_i`,
`measurement_j`), discarding everything before and between them. The
verifier recomputes each nonce as H(prior_response || rand), so the chain
must be contiguous; the project's own reporting server
(`crates/roughenough-reporting-server/src/validation.rs`,
`validate_chaining`) rejects any report whose entries do not chain from the
first entry. Since `validate_causality` compares all pairs (i, j), only the
(0, 1) pair currently yields an acceptable report.

**Change.** Build the report from measurements 0 through max(i, j) inclusive,
in the order performed. The first entry omits `rand` (its nonce was not
chained); every later entry carries the `rand` used to derive its nonce from
the previous response. Extend `CausalityViolation`
(`validation.rs` ~lines 46-48) or the reporting call path to carry the
indices (i, j) plus access to the full measurement list, rather than clones
of two measurements. Set the content type per 4.3.

**Tests (new).** In `reporting.rs`:
- Violation between measurements (0, 2) of a 3-measurement sequence
  produces a 3-entry report in order, first entry without `rand`, entries 2
  and 3 with the correct `rand` values.
- Cross-check: feed that serialized report into the reporting server's
  `validate_report`/`validate_chaining` (add
  `roughenough-reporting-server` as a dev-dependency of the client crate, or
  put the test in `crates/roughenough-integration`) and assert it validates.
  This agreement test is the point of the phase; do not skip it.

**Acceptance.** Every violation `validate_causality` can emit produces a
report the reporting server accepts (given a real violation; see 4.2).

## 4.2 Reporting server: verify the violation, bound the storage, stop leaking IPs

**Problem.** `crates/roughenough-reporting-server/src/validation.rs`
(~lines 143-174) checks signatures and nonce chaining but never checks the
claim itself -- that MIDP_i - RADI_i > MIDP_j + RADI_j for some i < j -- so
any two chained honest measurements are stored as a "malfeasance report".
`storage.rs` (~lines 40-56) inserts into a HashMap with no cap, TTL, or rate
limit; `main.rs` (~line 17) binds 0.0.0.0:3000. Additionally
`validate_chaining` rejects a first entry that CARRIES a `rand`
value; RFC 8.4.1 says rand "MAY be omitted" from the first entry -- carrying
one is not an error.

**Change.**
1. Causality check: after chain validation, parse MIDP and RADI from each
   entry's response and require at least one pair (i < j) with
   `midp_i.saturating_sub(radi_i) > midp_j.saturating_add(radi_j)`.
   Reject otherwise with a 4xx and a distinct error body
   ("no causality violation demonstrated").
2. First-entry `rand`: accept and ignore it (the first nonce is unchained by
   definition); only reject when a LATER entry lacks `rand` or fails the
   chain recomputation.
3. Storage bounds: hard cap on stored reports (const, e.g. 10_000) -- reject
   with 503 or evict oldest when full (pick one and document it in the
   handler); per-source-IP submission limit per interval (simple fixed-window
   counter in the storage layer is fine); axum body-size limit set explicitly
   to a value derived from the max plausible report (entries are bounded by
   the client's measurement rounds; 256 KB is generous) rather than relying
   on the default.
4. `source_ip` stays in stored reports AND in GET responses -- it is
   public information. Do not redact it.
5. Media type (with 4.3): accept `application/roughtime-malfeasance+json`;
   continue accepting `application/json` for compatibility.

**Tests (new).** In the reporting-server test suite
(`tests/server_tests.rs` plus a new inline `mod tests` in `validation.rs` --
the crate currently has no inline tests):
- Chained report with NO causality violation -> rejected (this is the test
  whose absence let the bug ship).
- Chained report WITH a violation -> accepted.
- First entry carrying `rand` -> accepted.
- Cap: submit cap+1 valid reports, assert the configured full-behavior
  (503 or eviction) occurs.
- Rate limit: burst from one source trips the limit; another source is
  unaffected.

**Acceptance.** The server stores only reports that demonstrate a violation,
within fixed memory bounds.

## 4.3 Correct media type on submission

**Problem.** `reporting.rs` (~line 112) POSTs `application/json`; RFC 8.4.1 /
12.4.2 register `application/roughtime-malfeasance+json`.

**Change.** Client sends the registered type. Server (4.2) accepts both.

**Tests (new).** Client unit test asserting the header on the built request;
server test asserting both content types are accepted.

**Acceptance.** Header matches the RFC registration.

---

# Phase 5: RFC conformance polish

## 5.1 Stop answering private-use version numbers

**Problem.** `crates/roughenough-protocol/src/protocol_ver.rs`:
`is_draft()` treats EVERY value with the high bit set (except the 0xffffffff
sentinel) as a supported draft, and `negotiate()` picks the numerically
highest. RFC 12.2 splits that space: 0x80000000-0xbfffffff is
experimental/draft use, 0xc0000000-0xffffffff is private use. A client
offering 0xc0000001 gets a signed response claiming version 0xc0000001 --
semantics this implementation has never seen, violating RFC 5.2.5 ("the
server MUST ensure that the version number corresponds with the rest of the
packet contents"). The test `arbitrary_draft_version_is_negotiated`
(`crates/roughenough-server/src/requests.rs` ~line 420) currently pins the
old behavior.

**Change.** Narrow `is_draft()` to the draft/experimental range only:
`(0x8000_0000..=0xbfff_ffff).contains(&self.0)`. Keep the existing
"answer any draft revision uniformly" policy within that range (the doc
comment at the top of the file states this policy; update it to note the
private-use exclusion and cite RFC 12.2). Update
`arbitrary_draft_version_is_negotiated` to use a value inside the draft
range, and keep it -- the uniform-draft policy is intentional.

**Tests (new/changed).** In `protocol_ver.rs`:
- 0x80000001 and 0xbfffffff: `is_supported()` true.
- 0xc0000000, 0xc0000001, 0xfffffffe: `is_supported()` false;
  `from_u32` returns `None`; `negotiate` over a list containing only such
  values returns `None`.
In `requests.rs`: a request offering only 0xc0000001 receives no response
(no common version path).

**Acceptance.** The server never signs a response bearing a private-use
version number.

## 5.2 Document the deliberate MAX_VERSIONS deviation

See "Explicit non-goals". Comment only; no behavior change; no new tests.

---

# Phase 6: Tests and fuzzing infrastructure

## 6.1 Fuzz the client's real input surface

**Problem.** `fuzz/fuzz_targets/fuzz_response_parse.rs` calls
`Response::from_wire`; the client actually calls `Response::from_frame`
(`client.rs` ~line 324, `sequence.rs` ~line 85), so the framing layer
(`crates/roughenough-protocol/src/wire.rs` ~lines 71-96, including
`truncate_remaining`) is fuzzed only via the request path. Also:
`use_srv` is dead in `fuzz_request_parse.rs` (~line 13);
`fuzz/corpus/fuzz_wire_format/` holds 145 files for a deleted target;
`fuzz/` is workspace-excluded so nothing in CI ever compiles the targets;
dependabot ignores `fuzz/`'s lockfile.

**Change.**
1. In `fuzz_response_parse.rs`, fuzz BOTH entry points on the same input:
   `let _ = Response::from_frame(data); let _ = Response::from_wire(data);`
   (mirroring how `fuzz_request_parse.rs` handles frames).
2. Remove the dead `use_srv` binding.
3. Delete `fuzz/corpus/fuzz_wire_format/` (or fold any interesting inputs
   into the response corpus first with a quick
   `cargo +nightly fuzz run fuzz_response_parse fuzz/corpus/fuzz_wire_format -runs=0`
   triage).
4. Add a CI job (in `.github/workflows/rust.yml`) that runs
   `cargo +nightly fuzz build` so targets cannot bit-rot; ~1 minute.
5. Add a `fuzz/` entry to `.github/dependabot.yml`.
6. After landing, run each target locally for at least an hour
   (`cargo +nightly fuzz run fuzz_response_parse`) and triage before release.

**Tests.** The fuzz build job IS the test. Additionally seed the response
corpus with a max-size (32-element PATH) framed response from 1.4's test.

**Acceptance.** CI fails if a fuzz target stops compiling;
`Response::from_frame` appears in a fuzz target.

## 6.2 Adversarial response parsing tests

**Problem.** `response.rs` has ~4 tests (happy-path and offset arithmetic)
versus ~20 for requests; there is `tests/adversarial_request_tests.rs` but no
response counterpart. `tags/dele.rs`, `tags/mtype.rs`, `tags/nonce.rs`,
`tags/pubk.rs`, and `tags/srv.rs` have no test modules.

**Change.** Add `crates/roughenough-protocol/tests/adversarial_response_tests.rs`
mirroring the request suite's approach: start from a valid serialized
response (there is a test vector near `response.rs:344`) and mutate. Cases,
each asserting a clean `Err` (never a panic):
- missing each mandatory tag (SREP, CERT, INDX, PATH, NONC, TYPE, VER);
- out-of-order and duplicate tags;
- truncated SREP, CERT, DELE, and PATH values (lengths off by 1, 4, half);
- PATH length not a multiple of 32; PATH > 32 elements;
- TYPE != 1; declared frame length shorter and longer than the buffer;
- trailing bytes after the frame (must be ignored per `truncate_remaining`).
Add minimal round-trip + reject-bad-length tests to the five untested tag
modules.

**Acceptance.** Response parsing has failure-path coverage comparable to
request parsing.

## 6.3 Integration tests must exercise the framed path and real batching

**Problem.** `crates/roughenough-integration/src/lib.rs` feeds `add_request`
unframed `request.as_bytes()` (~lines 58, 92, 133) while production feeds the
framed datagram and the client hashes `as_frame_bytes()` -- internally
consistent, so the tests pass, but structurally unable to catch a framing
mismatch between server hashing and client verification (exactly the bug
class of 3.4). `main.rs` claims to test "multi-batch behavior" with `-n 50`,
but each request is a separate blocking round trip, so batches are always
size 1 and PATH is always empty. The wrong-key negative test (~lines 129-160)
accepts ANY nonzero exit, so a crash also "passes". Port 2003 is hardcoded.

**Change.**
1. In `lib.rs`, switch the three call sites to framed bytes
   (`as_frame_bytes()` or equivalent) so the in-process tests hash exactly
   what production hashes.
2. Add a true multi-request-batch test: submit N > 1 framed requests to one
   `add_request`/`process_responses` cycle in-process, and verify EVERY
   client proof against the shared ROOT (nonzero PATH). If feasible over the
   wire, also fire N concurrent client sockets at a live server and require
   at least one response with a non-empty PATH.
3. Tighten the wrong-key test: assert the client's exit code/stderr matches
   the specific validation failure (signature mismatch), not merely nonzero.
4. Pick the server port dynamically (bind port 0, read back the local addr)
   so parallel test runs cannot collide.
5. Fix the `test_utils` trap: `create_interaction_pair_with_nonce`
   (`crates/roughenough-server/src/test_utils.rs` ~lines 59-91) never calls
   `clear()`, so a second call on one context trips its own internal assert.
   Call `clear()` at entry or document + assert the single-use contract.

**Acceptance.** A deliberate framing bug (e.g. temporarily hashing unframed
bytes in `responses.rs`) makes the integration suite fail. Verify this once
by hand before merging; note it in the PR.

## 6.4 Unit tests for untested client modules

**Problem.** Zero tests in `sequence.rs` (chained-nonce derivation,
~lines 105-110, is what makes cross-server malfeasance detection sound),
`transport.rs` (sole construction site of `ClientError::ServerTimeout`), and
`client.rs`.

**Change/Tests (new).**
- `sequence.rs`: unit-test nonce chaining -- given measurement k's response
  bytes and a fixed rand, assert nonce_{k+1} == H(response_frame || rand)
  exactly as `crates/roughenough-common/src/crypto.rs` computes it (hash over
  the full frame including framing, per RFC 8.2). Refactor the derivation
  into a pure function if needed for testability.
- `sequence.rs`: stale-datagram test if a seam exists -- a response not
  matching the current round's nonce should be skipped/drained rather than
  aborting the sequence (see review finding "stale-datagram desync",
  `sequence.rs` ~lines 79-85: one duplicated datagram from round k is
  consumed as round k+1's answer and kills the run). Implementing the drain
  is in scope here: on proof/nonce mismatch, retry the receive until timeout
  rather than failing immediately.
- `transport.rs`: timeout test against a socket that never answers
  (bind an OS-assigned local port, send, expect `ServerTimeout` within the
  configured budget).

**Acceptance.** The three modules have test modules; a duplicated datagram
no longer aborts a measurement sequence.

---

# Phase 7: Documentation and release hygiene

Small, mechanical, high-embarrassment-value. One PR is fine.

1. **README.md**: quick-start port 2002 -> 2003 everywhere (server default is
   2003 per `crates/roughenough-server/src/args.rs` ~line 31); fix package
   names in commands (`-p protocol` -> `-p roughenough-protocol`,
   `-p client` -> `-p roughenough-client`, ~lines 92, 118); document the
   client flags `-P/--protocol` (including that the default `V19` is
   draft-only and what that means for public servers), `-s/--set-clock`
   (with its new `-k` requirement), `-t/--timeout`, `-u`, and `-r`.
2. **doc/RELEASE-CHECKLIST.md**: fix all eight package names (~lines 15-22);
   add the missing crates to the publish list or mark them unpublishable
   (see item 8).
3. **Version strings**: replace `#[command(version = "2.0.0")]` with
   `#[command(version)]` (clap reads `CARGO_PKG_VERSION`) in
   `crates/roughenough-server/src/args.rs:8`,
   `crates/roughenough-client/src/args.rs:8`, and
   `crates/roughenough-keys/bin/keys.rs:18`. Test: `--version` output equals
   the crate version (one assertion per binary via `try_parse_from` or a
   trivial integration check).
4. **CHANGELOG.md**: populate `[Unreleased]` with the changes from this plan
   as they land (each phase's PR appends its entries).
5. **CONTRIBUTING.md**: make the unsafe policy match reality -- the
   exception list (~lines 153-155) must include
   `crates/roughenough-keys/src/online/aws_lc_ed25519.rs`; after 2.4 lands,
   `roughenough-server` can genuinely carry `#![forbid(unsafe_code)]` -- add
   it to `crates/roughenough-server/src/lib.rs` as part of 2.4 and say so
   here. Change keys crate `deny` -> documented exception or `forbid` where
   possible. Remove the reference to the nonexistent `tasks/` directory
   (~line 66). Fix "asynchronous" wording (~line 58) -- the server is a
   blocking mio poll loop on OS threads; also fix the same word in
   `crates/roughenough-server/Cargo.toml:4` (`description`).
6. **Small text fixes**:
   `crates/roughenough-protocol/src/error.rs:26` `UnexpectedMagic` message
   says `0x544f...` ("TOUGHTIM") -- correct to `0x524f...`;
   `crates/roughenough-protocol/src/wire.rs:7-10` comment quotes the RFC's
   little-endian constant while the code stores the byte-swapped form -- 
   rewrite the comment to explain the relationship;
   `doc/RFC-PROTOCOL.md` note that this implementation is UDP-only;
   `doc/REQUEST-FLOW.md` update the response-generation description (single
   lazy-template loop, called up to `MAX_BATCHES_PER_WAKEUP` times per
   wakeup) and soften the "no allocations" claim to "no steady-state
   allocations (see tests/alloc_tests.rs)".
7. **Dockerfile**: the dependency-cache layer omits
   `crates/roughenough-reporting-server/Cargo.toml` (a workspace member), the
   stub loop creates only `src/lib.rs` (missing `[[bin]]` stubs and keys'
   `bin/keys.rs`), and the `2>/dev/null || true` on the pre-build masks the
   failure -- so the layer is a silent no-op and every image build recompiles
   AWS-LC. Fix: copy all eight manifests plus `Cargo.lock`, create stubs for
   every lib AND bin target, and REMOVE `|| true` so a future breakage fails
   the build. Verify: `docker build .` twice; the second build's dependency
   layer must be cached.
8. **Publish guards**: add `publish = false` to
   `crates/roughenough-integration/Cargo.toml` and (unless publication is
   intended) `crates/roughenough-reporting-server/Cargo.toml`.
9. **Reporting server ops**: give `roughenough_reporting_server` a minimal
   clap CLI (`--listen <addr:port>`, default `0.0.0.0:3000`) instead of the
   hardcoded bind (`main.rs:17`), and state in its crate docs/README section
   that storage is in-memory and non-durable.
10. **.pre-commit-config.yaml**: align the clippy hook with CI:
    `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
11. **Dead code**: delete the unreachable `stub_backend` module in
    `crates/roughenough-keys/src/online/linuxkrs.rs` (~lines 469-509) -- the
    module is cfg-gated to Linux-only so its non-Linux stub can never
    compile.
12. **CausalityViolation shape**: covered by 4.1 (carries indices/chain);
    ensure docs describing two-measurement reports are updated with it.

**Acceptance.** A new user can follow README start-to-finish successfully;
`docker build` uses the dependency cache; every copy-pasteable command in the
docs runs.

---

# Phase 8: Performance and simplification (benchmark-gated)

Rules for this phase, per CLAUDE.md: measure a baseline FIRST
(`cargo bench -p roughenough-server` and `-p roughenough-merkle`; divan is
already configured with an allocation profiler in
`crates/roughenough-server/benches/server_ops.rs`). Report medians and
percentiles, never averages. Any change that does not measure as an
improvement is reverted. Land each item as its own commit with before/after
numbers in the message. Items 8.1-8.3 are the ones with measured byte counts
behind them; 8.4+ are smaller.

## 8.1 Batch response sends with `sendmmsg` (Linux)

**Problem.** `crates/roughenough-server/src/network.rs` issues one `send_to`
per response (~line 58); a full 64-request batch costs 64 send syscalls
(plus 64 receives) against roughly one Ed25519 signature of actual work.
Syscall count is very likely the dominant per-batch cost. `sendmmsg` on the
existing mio backend collapses the sends into one syscall per batch for
roughly 50 lines of change.

**Change.** `process_responses` already emits a batch's responses
back-to-back. Buffer the (bytes, addr) pairs for a batch and flush with one
`sendmmsg` on Linux (`libc::sendmmsg` on the mio socket's raw fd, or the
`nix` crate if it is already in the dependency tree -- prefer no new
dependency; a small `unsafe` block wrapping `sendmmsg` is acceptable ONLY in
a Linux-gated module with the safety contract documented, which then needs a
CONTRIBUTING.md exception per Phase 7.5). Non-Linux keeps the per-packet
`send_to` loop. Handle partial sends (`sendmmsg` returning < N) by resuming
from the first unsent message. `recvmmsg` is explicitly OUT of scope for
this item (it restructures `collect_requests`'s buffer reuse); file it as a
follow-up after 8.1's numbers are in.

**Tests (new).** The existing over-the-wire tests
(`tests/worker_loop_tests.rs`, integration suite) already validate delivery;
add a resilience test that a batch of 64 responses all arrive (loopback,
count received datagrams). Add a partial-send unit test if the flush is
factored into a testable function.

**Acceptance.** Benchmarked improvement in batch processing/throughput at
batch sizes 16-64 on Linux; identical behavior (test suite) on macOS.

## 8.2 Stop cloning the response template per request

**Problem.** `crates/roughenough-server/src/responses.rs` (~line 170) clones
a 1480-byte `Response` (1032 of which is a max-size `MerklePath` array;
real depth <= 6 at batch cap 64) once per request, then immediately
overwrites the only per-request fields.

**Change.** Mutate `self.version_templates[slot].1` in place: set path,
nonce, and index (~lines 171-173) directly on the template and serialize
from it. The template's `cert`, `srep`, and `sig` are untouched inside the
loop; compute the Merkle path before taking the `&mut` borrow (the borrows
split cleanly across disjoint fields per the review). Also fold in the
related per-batch churn (~lines 142-161): keep long-lived `Response`
templates in a fixed 4-slot array, refreshing `cert`/`srep`/`sig` per batch
instead of building `Response::default()` per distinct version.

**Tests.** Existing response-correctness and integration tests are the
guard; add one asserting two consecutive batches with different versions
produce correct, independent responses (no state bleed between batches
through the reused templates -- this is the new bug risk this change
introduces).

**Acceptance.** `alloc_tests.rs` still passes; divan shows reduced
time/allocations at batch 64; no cross-batch state bleed test failures.

## 8.3 Shrink `Request` and `PendingRequest`

**Problem.** Two compounding sizes (measured with `-Zprint-type-sizes` at
review): (a) `RequestPlain`/`RequestSrv`
(`crates/roughenough-protocol/src/request.rs` ~lines 201, 318) each carry a
944-byte `padding` array that is only ever zeros -- parsing discards
received ZZZZ bytes (~lines 172-177) and serialization writes zeros -- so
every parsed `Request` is 1064 bytes; (b) `PendingRequest`
(`crates/roughenough-server/src/responses.rs` ~lines 15-20) stores a whole
`Request` by value when the batch loop reads only `nonc()`, `version`, and
`src_addr`, making the 64-slot pending Vec ~70 KB of mostly zeros.

**Change.**
1. Delete the `padding` field from both request structs; in `to_wire`, write
   from `const ZERO_PADDING: [u8; MAX_PADDING] = [0; MAX_PADDING];`. Remove
   the `Default`/`from_parts` zeroing and the round-trip assertion
   `assert_eq!(decoded.padding, req.padding)` (~line 472), which only ever
   compared zeros to zeros.
2. Change `PendingRequest` to store `nonce: Nonce` (+ version + src_addr)
   instead of `request: Request`; update `responses.rs` (~line 172) to read
   the stored nonce.

**Tests.** Request round-trip and adversarial suites already pin wire
behavior; add an explicit test that a serialized request's ZZZZ region is
all zeros and the frame is >= 1024 bytes (padding math unchanged). A
`size_of` assertion (`assert!(size_of::<PendingRequest>() < 128)`) documents
the win and catches regressions.

**Acceptance.** Wire bytes are byte-identical before/after (add a golden
test comparing a serialized request against a pre-change hex fixture);
benchmarks at batch 64 do not regress (expected: improvement).

## 8.4 Small server-side wins (bundle into one benchmarked PR)

- `MerkleTree::reserve` (`crates/roughenough-merkle/src/lib.rs`
  ~lines 61-92): reserve `num_leaves.next_power_of_two()` per level so odd
  level counts plus the padding-node push (~line 150) never reallocate, even
  on the first batch (currently warm-up-only reallocation, e.g. at
  batch 48).
- `collect_requests` stack buffer (`network.rs` ~line 37): move the
  1473-byte buffer (size updated by 3.4) into a `NetworkHandler` field to
  avoid re-zeroing up to 8x per wakeup.
- `ResponseMetrics.batch_sizes` (`metrics/types.rs` ~lines 60-104):
  `Vec<usize>` of fixed length 64 -> `[u32; 64]`, making the struct `Copy`
  and removing an allocation per metrics publish.

**Tests.** Existing merkle/metrics/network tests; add a merkle test
asserting no reallocation across first-batch sizes 1..=64 (capture pointer
or track capacity before/after `compute_root`).

## 8.5 Protocol-crate simplifications (no wire-behavior change)

Each is independent; wire bytes must be provably unchanged (round-trip and
golden tests are the gate).

1. **Fixed-size tag macro**: `tags/nonce.rs`, `tags/root.rs`,
   `tags/pubk.rs`, `tags/sig.rs` are the same ~5 trait impls around
   `FixedTag<32|64>`; `tags/srv.rs` hand-rolls the same thing without
   `FixedTag` and is consequently not `Copy` (forcing `server.clone()` at
   `request.rs` ~lines 68, 340). Write `fixed_tag!(Name, SIZE, "LABEL")`
   next to the existing `make_header_n!` (`header.rs` ~line 205), port all
   five, make `SrvCommitment` a `FixedTag<32>` (becomes `Copy`; delete the
   clones). ~250 lines removed.
2. **Merge `RequestedVersions`/`SupportedVersions`**
   (`tags/ver.rs`, `tags/vers.rs`): identical delegating wrappers around
   `VersionList` differing only in `Default` and a Debug label. Collapse to
   one type (or type aliases over `VersionList` with two const
   constructors). ~100 lines removed.
3. **`root_from_paths` as a free function**
   (`crates/roughenough-merkle/src/lib.rs` ~line 205): reads no tree state;
   every caller (`validation.rs` ~line 202, integration `lib.rs` ~line 181)
   builds a throwaway heap-allocating `MerkleTree::new()` to reach it.
   Make it `pub fn root_from_paths(index, init_data, paths)` at module
   level; delete the throwaway trees at call sites.
4. **`dele_prefix`/`srep_prefix`** (`protocol_ver.rs` ~lines 87-101): both
   branches return the same constant; the panic arm is unreachable after
   `negotiate()` filtering. Replace with two associated consts; update the
   callers (`onlinekey.rs` ~line 119).
5. **Read-only `ParseCursor` path**: `ParseCursor` holds `&mut [u8]`
   (`cursor.rs` ~line 10) so read-only parsing of borrowed bytes forces
   owned copies -- `find_value_range` (`header.rs` ~line 165) never mutates,
   and client validation (`validation.rs` ~lines 131-152) performs about six
   up-to-1 KB heap copies per validated response as a result. Split reads
   onto `&[u8]` (only `put_*` and `truncate_remaining` mutate). This is the
   largest refactor in this list (touches every `FromWire` impl signature);
   do it last, alone, with the full test + fuzz suite as the gate.

**Tests.** For each: existing round-trip suites plus a golden-bytes fixture
test (serialize a known request and response; compare hex against a fixture
generated BEFORE the refactor) added at the start of this item and kept
permanently.

## 8.6 Server public-surface reduction and doc sync

`crates/roughenough-server/src/lib.rs` exports `args`, `keysource`,
`metrics`, `network`, `requests`, and `responses` fully public with no
external consumers beyond the crate's own binary, benches, and tests. Reduce
to `pub(crate)` except what `benches/server_ops.rs` and the `test-utils`
feature need. Delete the empty `mod tests {}` stub in `network.rs`
(~lines 81-82). (`URING.md`, a design document for unimplemented io_uring
work, has already been deleted; if a copy resurfaces, delete it.)

---

# Suggested sequencing and PR grouping

1. PR 1: 1.1, 1.2, 1.3 (client safety trio -- smallest, highest value)
2. PR 2: 1.4, 1.5, 1.6
3. PR 3: 2.1 (cloud backend Results -- largest single item)
4. PR 4: 2.2, 2.3, 2.4
5. PR 5: 3.1, 3.2, 3.3
6. PR 6: 3.4, 3.5, 3.6, 3.7
7. PR 7: 4.1 + 4.2 + 4.3 together (client and server must agree)
8. PR 8: 5.1, 5.2
9. PR 9: 6.1, 6.2 (protocol test hardening)
10. PR 10: 6.3, 6.4
11. PR 11: Phase 7 (docs/release, mechanical)
12. PRs 12+: Phase 8 items individually, each with benchmarks

Every PR: clippy clean, fmt run, `cargo test --workspace` green, CHANGELOG
`[Unreleased]` entry appended.
