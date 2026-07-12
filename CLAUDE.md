# CLAUDE.md

Guidance for AI agents working with this repository.

## Project Overview

Rust implementation of the Roughtime protocol -- a cryptographic time synchronization protocol providing authenticated timestamps with proof against server malfeasance. Includes client and server components. Strives to comply with the RFC (see `doc/draft-ietf-ntp-roughtime-*.txt`).

## Architecture

Cargo workspace with eight crates:

- **protocol**: Core wire format, request/response types, tag definitions, TLV encoding
- **server**: UDP server using mio for async I/O, with batching and Merkle tree signatures
- **client**: CLI client with output formatting, validation, optional malfeasance reporting (`reporting` feature)
- **common**: Shared cryptography and encoding utilities
- **merkle**: Merkle tree with Roughtime-specific leaf/node tweaks (SHA-512, first 32 bytes)
- **keys**: Key material handling with backend options (Linux KRS, SSH agent, PKCS#11, AWS KMS/Secrets Manager, GCP KMS/Secret Manager)
- **reporting-server**: Web server for malfeasance reports 
- **integration**: End-to-end tests spawning actual server/client processes

Fuzzing targets in **fuzz**: `fuzz_request_parse`, `fuzz_response_parse`, `fuzz_structured`.

## Protocol Implementation Notes

See `doc/RFC-PROTOCOL.md` for protocol details. See `doc/PROTECTION.md` for seed protection strategies.

- Wire encoding: 8-byte 'ROUGHTIM' magic, 4-byte LE length, then TLV message bytes
- Only Requests and Responses are framed; no other messages use framed encoding
- Response sizes vary with Merkle tree PATH length
- Server uses callback-based batching for O(1) allocations
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

# Integration test (build first, then run from project root)
cargo build && target/debug/roughenough_integration_test

# Reporting server (not a default member; build and test with -p)
cargo build -p roughenough-reporting-server
cargo test -p roughenough-reporting-server

# Keys backends are feature-gated and tokio is only present with a
# longterm-* cloud feature; check a specific combination with:
cargo check -p roughenough-keys --features longterm-aws-kms
```

### Code Quality
```bash
cargo +nightly fmt             # Format (requires nightly)
cargo clippy                   # Lint
cargo check                    # Type check
```

### Benchmarking
```bash
cargo bench                            # All benchmarks
cargo bench -p roughenough-merkle      # Specific crate
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
cargo run --bin roughenough_server          # Server
cargo run --bin roughenough_client -- -h    # Client (see --help for options)
cargo run -p roughenough-keys --bin roughenough_keys -- --help  # Keys tool
cargo run -p roughenough-reporting-server --bin roughenough_reporting_server  # Reporting server (port 3000)
```

## Commenting Guidelines

Comments explain **why**, not what. Do not narrate code or duplicate names in English.

- Comment: intent, workarounds, external context, assumptions, edge cases
- Do not comment: obvious logic, removed/obsolete code paths (delete stale comments with deleted code)

## Rust Development Guidelines

- Prefer `?` over explicit error handling
- Use `match` for exhaustive patterns, not if-else chains
- Prefer iterators over manual loops
- Prefer borrowing over cloning; `&str` over `String` for parameters when ownership is not needed
- Use `const` not `static` for compile-time constants
- Implement `From` for conversions; use `#[derive()]` for common traits

## Benchmarking and Performance

- Treat performance changes as experiments: assume the change does NOT help until benchmarks prove otherwise
- Measure baseline before changes, compare after. Reject changes that do not show improvement.
- NEVER use averages. Use percentiles, medians, and distributions.
- Show all measurements, not cherry-picked results.
- Run `cargo bench -p roughenough-merkle` for merkle changes, `cargo bench -p roughenough-server` for server changes.

## Communication Style

- Be clear, concise, and precise. No marketing language ("production ready", "enterprise grade", etc.).
- Skip affirmations ("great question!"). Respond directly.
- Challenge flawed ideas. Ask clarifying questions when ambiguous.
- ASCII only. Never use unicode or emojis in communication, comments, strings, or commits.

## Operational Rules

- NEVER ignore or disable tests to make them pass
- ALWAYS benchmark before and after performance changes
- Run `cargo clippy` and `cargo +nightly fmt` before committing
- Include Cargo.lock changes in commits when dependencies change
- Do not include "committed by Claude" language in commit messages
- Use todo lists for complex tasks
- Reference `doc/draft-ietf-ntp-roughtime-*.txt` and `doc/RFC-PROTOCOL.md` for protocol questions
- Reference `doc/PROTECTION.md` for key management questions

