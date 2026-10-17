# CLAUDE.md

Guidance for AI agents working with this repository.

## Project Overview

Rust implementation of the Roughtime protocol -- a cryptographic time synchronization protocol providing authenticated timestamps with proof against server malfeasance. Includes client and server components. Strives to comply with RFC 10049 (see `doc/RFC-10049.txt`).

## Architecture

Cargo workspace with eight crates under `crates/roughenough-*`:

- **protocol**: Core wire format, request/response types, tag definitions, TLV encoding
- **server**: UDP server using mio for async I/O, with batching and Merkle tree signatures
- **client**: CLI client with output formatting, validation, optional malfeasance reporting (`reporting` feature)
- **common**: Shared cryptography and encoding utilities, and the clock source
- **merkle**: Merkle tree with Roughtime-specific leaf/node tweaks (SHA-512, first 32 bytes)
- **keys**: Key material handling. Online seed backends: in-memory (default), Linux KRS, SSH agent, PKCS#11. Long-term seed protection via the `roughenough_keys` tool: AWS KMS/Secrets Manager, GCP KMS/Secret Manager
- **reporting-server**: Web server for malfeasance reports 
- **integration**: End-to-end tests spawning actual server/client processes; also a load generator (`roughenough_load_test`)

Fuzzing targets in **fuzz** (excluded from the workspace): `fuzz-request-parse`, `fuzz-response-parse`, `fuzz-structured`.

## Protocol Implementation Notes

See `doc/RFC-10049.txt` for protocol details, `doc/REQUEST-FLOW.md` for the end-to-end request path through the server, and `doc/PROTECTION.md` for seed protection strategies.

- Wire encoding: 8-byte 'ROUGHTIM' magic, 4-byte LE length, then TLV message bytes
- Only Requests and Responses are framed; no other messages use framed encoding
- Response sizes vary with Merkle tree PATH length
- Server uses callback-based batching with zero steady-state allocations on the hot path (enforced by `crates/roughenough-server/tests/alloc_tests.rs`)
- Little-endian encoding throughout
- All crates use Rust 2024 edition

## Development Commands

### Build and Test
```bash
cargo build                    # Build default members (excludes reporting-server)
cargo build --workspace        # Build all crates including reporting-server
cargo build --release          # Release build
cargo test                     # Test default members
cargo test --workspace         # Test all crates including reporting-server
cargo test -p roughenough-protocol    # Test specific crate

# End-to-end test of the server and client binaries from the same profile
cargo build && cargo run --bin roughenough_integration_test
cargo build --release && cargo run --release --bin roughenough_integration_test

# Reporting server (not a default member; build and test with -p)
cargo build -p roughenough-reporting-server
cargo test -p roughenough-reporting-server

# Keys backends are feature-gated and tokio is only present with a
# longterm-* cloud feature; check a specific combination with:
cargo check -p roughenough-keys --features longterm-aws
```

### Code Quality
```bash
cargo +nightly fmt             # Format (requires nightly)
cargo +nightly fmt --check     # Format check (as pre-commit runs it)
cargo clippy --workspace --all-targets --all-features -- -D warnings   # Lint (as CI/pre-commit run it)
cargo check                    # Type check
```

### Benchmarking
```bash
cargo bench                            # All benchmarks
cargo bench -p roughenough-merkle      # Specific crate (merkle, server, protocol have benches)
```

### Fuzzing
```bash
cargo +nightly fuzz list                    # List targets
cargo +nightly fuzz run <target>            # Run fuzzing
cargo +nightly fuzz cmin <target>           # Minimize corpus
```

### Code Coverage
```bash
# Install: cargo install cargo-llvm-cov
./coverage.sh                  # HTML report, opens in browser
./coverage.sh --lcov           # lcov format for CI
./coverage.sh --help           # All options
```

### Running Binaries
```bash
cargo run --bin roughenough_server -- --insecure-zero-seed   # Server (testing; production needs --seed-file)
cargo run --bin roughenough_client -- -h    # Client (see --help for options)
cargo run -p roughenough-keys --bin roughenough_keys -- --help  # Keys tool
cargo run -p roughenough-reporting-server --bin roughenough_reporting_server  # Reporting server (port 3000)
```

## Commenting Guidelines

Comments explain **why**, not what. Do not narrate code or duplicate names in English.

- Comment: intent, workarounds, external context, assumptions, edge cases
- Do not comment: obvious logic, removed/obsolete code paths (delete stale comments with deleted code)

## Benchmarking and Performance

- Treat performance changes as experiments: assume the change does NOT help until benchmarks prove otherwise
- Measure baseline before changes, compare after. Reject changes that do not show improvement.
- NEVER use averages. Use percentiles, medians, and distributions.
- Show all measurements, not cherry-picked results.
- Run `cargo bench -p roughenough-merkle` for merkle changes, `cargo bench -p roughenough-server` for server changes, `cargo bench -p roughenough-protocol` for wire-format changes.

## Communication Style

- Be clear, concise, and precise. No marketing language ("production ready", "enterprise grade", etc.).
- Skip affirmations ("great question!"). Respond directly.
- Challenge flawed ideas. Ask clarifying questions when ambiguous.
- ASCII only. Never use unicode or emojis in communication, comments, strings, or commits.

## Operational Rules

- NEVER ignore or disable tests to make them pass
- ALWAYS benchmark before and after performance changes
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo +nightly fmt` before committing (matches CI and pre-commit)
- Include Cargo.lock changes in commits when dependencies change
- Do not include "committed by Claude" language in commit messages
- Use todo lists for complex tasks
- Reference `doc/RFC-10049.txt` for protocol questions
- Reference `doc/PROTECTION.md` for key management questions
- Reference `doc/BPF-FILTER.md` for the Linux socket filter and how to test it
- Reference `doc/RELEASE-CHECKLIST.md` when preparing a release

