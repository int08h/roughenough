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
cargo build                    # Build workspace (excludes reporting-server)
cargo build --release          # Release build
cargo test                     # Run all tests
cargo test -p protocol         # Test specific crate

# Integration test (build first, then run from project root)
cargo build && target/debug/roughenough_integration_test

# Reporting server (separate build)
cd crates/reporting-server && cargo build
```

### Code Quality
```bash
cargo +nightly fmt             # Format (requires nightly)
cargo clippy                   # Lint
cargo check                    # Type check
```

### Benchmarking
```bash
cargo bench                    # All benchmarks
cargo bench -p merkle          # Specific crate
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
cargo run -p keys --bin roughenough_keys -- --help  # Keys tool
cd crates/reporting-server && cargo run --bin roughenough_reporting_server  # Reporting server (port 3000)
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
- Run `cargo bench -p merkle` for merkle changes, `cargo bench -p server` for server changes.

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

<!-- grove:start -->
## Code navigation: grove for structure, shell for the rest

**grove** is a tree-sitter engine for *structural* code questions — byte-precise,
token-cheap (languages: bash, json, rust). Its tools are **deferred** MCP tools; load them in
one ToolSearch when a code question lands (don't default to a search agent or grep):
`mcp__grove__outline`, `mcp__grove__symbols`, `mcp__grove__source`, `mcp__grove__callers`, `mcp__grove__definition`, `mcp__grove__map`, `mcp__grove__check`.

**Use grove for named symbols and relationships** (every result carries a stable
`symbol-id`, `<lang>:<relpath>#<name>@<row>`, to pass forward; lines 1-based):
- What's in a file (skeleton, not the whole file) → `mcp__grove__outline` (`detail:0` if > 500 lines).
- Where a fn / type / struct / macro is defined → `mcp__grove__symbols` with `name` → `mcp__grove__source` with the id.
- One symbol's exact body → `mcp__grove__source`.
- Who calls it → `mcp__grove__callers`.
- Go-to-def from a usage (scope-aware, follows imports cross-file) → `mcp__grove__definition` with `at` (file:line:col).
- How a directory connects → `mcp__grove__map` (one call; prefer over many `mcp__grove__source`).
- Syntax after an edit → `mcp__grove__check`.

**Use the shell — the right tool, not a fallback — when grove can't see the target:**
- Text, not a symbol (a string, log / error message, config key, a macro's *value*,
  a constant, a flag, a TODO) → `grep -rn` / `rg`. grove finds definitions, not text.
- Non-code files (Makefiles, configs, data, docs) → `grep` / `read`.
- A quick fact (path exists, `ls`, `wc -l`, `find`, read a small file) → shell.

**Combine** (same 1-based lines, same bytes): `grep` a literal's line → `mcp__grove__definition`
`at` to resolve its symbol · `mcp__grove__outline` → bounded `read` (`offset`/`limit`) for
adjacent symbols · `mcp__grove__map` / `mcp__grove__symbols` to locate → `grep` a constant inside.

Rule of thumb: want a **symbol** → grove first (don't `grep` / `read` for it). Want
**text or a quick fact** → shell. Combining is fine.
<!-- grove:end -->
