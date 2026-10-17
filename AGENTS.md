# AGENTS.md

Guidance for AI agents working with this repository.

## Project Overview

Rust implementation of the Roughtime protocol -- a cryptographic time synchronization protocol providing authenticated timestamps with proof against server malfeasance. Includes client and server components. Strives to comply with RFC 10049 (see `doc/RFC-10049.txt`).

## Architecture

Cargo workspace of eight crates; see [CONTRIBUTING.md](CONTRIBUTING.md#project-structure) for the crate map.

## Protocol Implementation Notes

See `doc/RFC-10049.txt` for protocol details, `doc/REQUEST-FLOW.md` for the end-to-end request path through the server, and `doc/PROTECTION.md` for seed protection strategies.

- Wire encoding: 8-byte 'ROUGHTIM' magic, 4-byte LE length, then TLV message bytes
- Only Requests and Responses are framed; no other messages use framed encoding
- Response sizes vary with Merkle tree PATH length
- Server uses callback-based batching with zero steady-state allocations on the hot path (enforced by `crates/roughenough-server/tests/alloc_tests.rs`)
- Little-endian encoding throughout
- All crates use Rust 2024 edition

## Development Commands

See [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, integration, bench, fuzz, and coverage commands.

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
