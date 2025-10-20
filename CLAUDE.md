# CLAUDE.md

This file provides guidance to AI agents (Claude, Gemini, etc) when working with code in this repository.

## Project Overview

This is a Rust implementation of the Roughtime protocol, a cryptographic time synchronization protocol that provides authenticated time stamps with cryptographic proof against server malfeasance. The implementation includes both client and server components. This project strives to be compliant with the RFC specification of the Roughtime protocol (the RFC is found in doc/draft-ietf-ntp-roughtime-14.txt).

## Architecture

The project is structured as a Cargo workspace with eight main crates:

- **protocol**: Core protocol implementation with wire format handling, request/response types, tag definitions, and custom type-length-value (TLV) encoding
- **server**: High-performance UDP server using mio for asynchronous I/O, with batching and Merkle tree signatures for efficient handling of multiple client requests
- **client**: Command-line client for querying Roughtime servers with flexible output formatting, validation, and optional malfeasance reporting (via the `reporting` feature)
- **common**: Shared utilities for cryptography and encoding functions used across other crates
- **merkle**: Merkle tree implementation with Roughtime-specific leaf/node tweaks using SHA-512 hashing (first 32 bytes only)
- **keys**: Key material handling for long-term and online key derivation with multiple backend options (Linux KRS, SSH agent, PKCS#11, AWS KMS/Secrets Manager, GCP KMS/Secret Manager) for secure seed storage and protection
- **reporting-server**: Web server for collecting and storing malfeasance reports
- **integration**: Integration tests that verify end-to-end server-client compatibility by spawning actual processes

There is fuzzing testing code in **fuzz**.

### Key Components

- **Request/Response Protocol**: Support for both plain requests (VER, NONC, TYPE, ZZZZ) and server-committed requests (VER, SRV, NONC, TYPE, ZZZZ). Responses include SIG, NONC, TYPE, PATH, SREP, CERT, INDX tags.
- **Wire Format**: Custom binary framing with 'ROUGHTIM' magic value (8 bytes), length field (4 bytes LE), followed by TLV-encoded message content. Requests are exactly 1024 bytes including framing and padding.
- **Batching**: Server batches multiple client requests and signs them together using a Merkle tree root to amortize expensive cryptographic operations
- **Key Material**: Long-term keys derive online keys with time-based validity periods. Online keys sign server responses to prove authenticity.
- **Validation**: Client validates server responses including signature verification and Merkle path validation
- **Cryptography**: Uses aws-lc-rs for Ed25519 signatures and SHA-512 hashing, with only the first 32 bytes of SHA-512 output used
- **Network**: Server uses mio for async high-performance UDP networking with configurable batching

## Development Commands

### Building
```bash
cargo build                        # Build all crates (excluding reporting-server)
cargo build --release              # Release build (excluding reporting-server)

# To build with reporting-server:
cd crates/reporting-server && cargo build
```

Note: The reporting-server is excluded from the workspace to reduce build times and dependencies. It can be built separately when needed.

### Testing
```bash
cargo test                             # Run all tests
cargo test -p protocol                 # Test specific crate
cargo test merkle::power_of_two        # Test specific module
```

### Running the server/client integration test
```bash
# Build (from root of project)
cargo build

# Run server/client integration test (from root of project)
target/debug/roughenough_integration_test
```

### Benchmarking
```bash
cargo bench                     # Run all benchmarks
cargo bench -p merkle          # Run benchmarks for specific crate
```

### Fuzzing
```bash
cargo +nightly fuzz run <target>  # Run fuzzing tests
cargo +nightly fuzz list          # List available fuzz targets

# Available targets:
cargo +nightly fuzz run fuzz_request_parse
cargo +nightly fuzz run fuzz_response_parse
cargo +nightly fuzz run fuzz_structured

# Minimize corpus after fuzzing
cargo +nightly fuzz cmin <target>

# Analyze crash
cargo +nightly fuzz run <target> <path-to-crash-artifact>
```

### Code Quality
```bash
cargo +nightly fmt    # Format code according to Rust style guidelines, **needs nightly rust** 
cargo clippy          # Run Rust linter for additional checks
cargo check           # Fast type checking without building
```

### Code Coverage
The project uses cargo-llvm-cov for code coverage measurement. Install it with:
```bash
cargo install cargo-llvm-cov
```

For convenience, use the provided coverage script:
```bash
# Generate HTML coverage report and open in browser
./coverage.sh

# Generate lcov format (for CI)
./coverage.sh --lcov

# Include all optional features
./coverage.sh --all-features

# Clean and regenerate coverage
./coverage.sh --clean

# See all options
./coverage.sh --help
```

Manual coverage commands:
```bash
# Generate HTML report for entire workspace
cargo llvm-cov --workspace --html

# Generate lcov format for CI integration
cargo llvm-cov --workspace --lcov --output-path lcov.info

# Coverage for specific crate
cargo llvm-cov -p protocol --html

# Coverage with all features enabled (example with keys crate features)
cargo llvm-cov --workspace --features "online-linux-krs,online-ssh-agent,online-pkcs11,longterm-aws-kms,longterm-gcp-kms" --html

# View coverage summary only
cargo llvm-cov --workspace --no-report --summary-only
```

Coverage reports are generated in `target/llvm-cov/html/` and can be viewed in a web browser. The CI pipeline automatically generates coverage reports and uploads them as artifacts.

### Running the server
```bash
# Debug build
cargo run --bin roughenough_server

# Release build
cargo run --release --bin roughenough_server

# Or directly:
target/debug/roughenough_server
target/release/roughenough_server

# With fixed time offset for testing:
cargo run --bin roughenough_server -- --fixed-offset="-60"  # 60 seconds behind UTC
```

### Running the client
```bash
# Basic usage
cargo run --bin roughenough_client -- hostname.com 2002

# With server key verification
cargo run --bin roughenough_client -- hostname.com 2002 -k <base64-or-hex-key>

# Multiple requests
cargo run --bin roughenough_client -- hostname.com 2002 -n 10

# Verbose output
cargo run --bin roughenough_client -- hostname.com 2002 -v

# Query multiple servers from JSON list
cargo run --bin roughenough_client -- -l servers.json

# Time format options
cargo run --bin roughenough_client -- hostname.com 2002 --epoch  # Unix timestamp
cargo run --bin roughenough_client -- hostname.com 2002 --zulu   # ISO 8601 UTC

# Enable malfeasance reporting
cargo run --bin roughenough_client -- hostname.com 2002 --report

# Or directly:
target/debug/roughenough_client hostname.com 2002
```

### Running the reporting server
```bash
# Run the malfeasance reporting server
cd crates/reporting-server && cargo run --bin roughenough_reporting_server

# The server listens on port 3000 by default
# Endpoints:
# POST /api/v1/reports     - Submit a malfeasance report
# GET  /api/v1/reports/{id} - Retrieve a report by ID
# GET  /health            - Health check endpoint
```

### Running the keys tool
```bash
# Build the keys tool
cargo build -p keys

# Run the keys command-line tool
cargo run -p keys --bin roughenough_keys -- --help

# Or directly:
target/debug/roughenough_keys --help
```

## Protocol Implementation Notes

See `doc/RFC-PROTOCOL.md` for a summary of the Roughtime protocol details. See `doc/PROTECTION.md` for information about long-term identity seed protection strategies using KMS, secret managers, Linux KRS, and SSH agent.

- Wire-encoded Requests and Responses are framed: 8-bytes of 'ROUGHTIM' magic value, 4-bytes of length (in little endian), and then the message bytes
- Only Requests and Responses are framed. No other messages have a framed wire encoding
- Requests are exactly 1024 bytes including the framing and padding
- Response sizes vary depending on the length of the included Merkle tree path (PATH tag)
- Responses include signatures over the current time and Merkle tree roots containing the client nonces
- Server implements callback-based batching of responses for O(1) allocations and pragmatic handling of Rust lifetime complications
- Wire format uses little-endian encoding throughout
- All crates use Rust 2024 edition

## Rust Development Guidelines

- Prefer `?` operator over explicit error handling where appropriate
- Use `match` for exhaustive pattern matching instead of if-else chains
- Leverage iterator methods instead of manual loops
- Follow ownership principles - prefer borrowing over cloning
- Use `const` for compile-time constants, not `static`
- Implement `From` trait for type conversions instead of custom methods
- Use `#[derive()]` for common traits when possible
- Prefer `&str` over `String` for function parameters when ownership isn't needed

## Dependencies and Build Configuration

Core dependencies used across crates:

- **Cryptography**: aws-lc-rs for Ed25519 signatures and SHA-512 hashing
- **Networking**: mio for async UDP I/O, socket2 for socket configuration
- **Time**: chrono for time handling and formatting, time-format for server time display
- **CLI**: clap for command-line argument parsing
- **Encoding**: data-encoding for base64/hex conversion, pastey for protocol message handling
- **Benchmarking**: divan for performance benchmarks
- **Error Handling**: thiserror for structured error types
- **Logging**: tracing and tracing-subscriber for structured logging
- **Concurrency**: crossbeam-channel for message passing, fastrand for random number generation

Dependencies for optional features:

- **Async Runtime**: tokio for async operations (keys and reporting-server crates)
- **Web Framework**: axum and tower for HTTP server (reporting-server)
- **HTTP Client**: ureq for reporting feature (client crate, optional)
- **Cloud Providers**: aws-sdk-kms, aws-sdk-secretsmanager, google-cloud-kms-v1, google-cloud-secretmanager-v1 for cloud key management (keys crate, optional)
- **Security**: zeroize for secure memory clearing (keys crate), linux-keyutils for Linux keyring access (keys crate, optional)
- **SSH**: ssh-agent-client-rs and ssh-key for SSH agent integration (keys crate, optional)

## Development Scripts

- **coverage.sh**: Convenient script for generating code coverage reports with cargo-llvm-cov

## Memories

- **NEVER** ignore or disable tests to get tests to pass
- **ALWAYS** use benchmarks to test before and after changes to ensure expected performance gains are realized
- For performance-critical changes in merkle tree operations, run `cargo bench -p merkle`
- For server performance, run `cargo bench -p server`
- Compare benchmark results before and after changes using the output metrics
- Review code as a Rust expert, thinking carefully about how to make the implementation idiomatic and simple
- Create a todo list when working on complex tasks to track progress and remain on track
- The server/client integration test spawns actual server and client processes to verify end-to-end compatibility
- Do not include "committed by Claude" type language in git commits comments
- When completing Rust code changes, run `cargo clippy` for linting and `cargo check` for type checking
- Run `cargo +nightly fmt` to ensure consistent code formatting before committing
- Check Cargo.lock for any dependency changes and include in commits when dependencies are updated
- When answering questions about Roughtime protocol specifics, reference `doc/draft-ietf-ntp-roughtime-14.txt` (the RFC) and `doc/RFC-PROTOCOL.md` for implementation details
- When discussing key management and seed protection, reference `doc/PROTECTION.md` for details on KMS, secret managers, and runtime protection strategies
- USE ASCII FOR **ALL** COMMUNICATION.

## Benchmarking and Performance Improvements

- Benchmarking is a critical part of all changes. Treat performance changes as a science experiment where the
  assumption is that the change will NOT improve performance. You must prove that the change does improve performance
  before you accept it and before the user will accept it. Be skeptical of claims about performance improvements!
- Think before you make changes. Think harder about the changes and how to test their effects. Use benchmarks to 
  measure baseline before your change and performance after a change. Do not assume anything about performance.
- Be data driven. Ground your conclusions in actual results. If benchmarks show there is no improvement from a 
  change that was intended to improve performance, reject the change and stick with the original code.
- NEVER use the average. NEVER. Use the language of science and mathematics to evaluate performance: percentiles, 
  medians, distributions, and other robust statistical measures.
- Do not cherry-pick results. Show the results across all measurements, not only those that are "interesting" or
  "relevant". Choose measurements that are representative of the overall performance of the system. 

## Communication Style

- CLEAR, CONCISE, AND ACCURATE COMMUNICATION IS VITAL.
- NEVER use "marketing language" like “production ready”, “enterprise grade”, "bulletproof implementation," or other
  superlatives and meaningless words. This style is confusing, makes communication less clear, and obscures the nuance
  needed for effective engineering communication. Speak like an expert using precise language.
- Skip affirmations and compliments. No “great question!” or “you’re absolutely right!” - just respond directly
  - Bad: “That’s a fascinating point! You're absolutely right!” 
  - Good: Directly respond
- Challenge flawed ideas openly when you spot issues
  - Bad: Agreeing when something’s wrong
  - Good: "That’s not quite right because...”
- Ask clarifying questions whenever my request is ambiguous or unclear
  - Bad: Guessing what I mean 
  - Good: “Are you asking about X or Y specifically?”
- When I make obvious mistakes, point them out with gentle humor or playful teasing
  - Bad: Ignoring errors
  - Good: "This seems incorrect, 2+2 isn’t 5. You finished kindergarten, right? ;)”
- Never generate unicode or emojis comments, strings, or commit messages. USE ASCII FOR **ALL** COMMUNICATION.

# Project Management Instructions 

## Source of Truth

- Tasks live under `/tasks/` 
- Every implementation decision starts with reading the corresponding Markdown task file.

## Defining Tasks

### Title

A clear brief title that summarizes the task.

### Description: (The "why")

Provide a concise summary of the task purpose and its goal. Do not add implementation details here. It should explain 
the purpose and context of the task. Code snippets should be avoided.

### Acceptance Criteria: (The "what")

List specific, measurable outcomes that define what means to reach the goal from the description. Use 
checkboxes (`- [ ]`) for tracking. When defining `## Acceptance Criteria` for a task, focus on **outcomes, 
behaviors, and verifiable requirements** rather than step-by-step implementation details.

Acceptance Criteria (AC) define *what* conditions must be met for the task to be considered complete. They should be 
testable and confirm that the core purpose of the task is achieved.

**Key Principles for Good ACs:**

- Outcome-Oriented: Focus on the result, not the method.
- Testable/Verifiable: Each criterion should be something that can be objectively tested or verified.
- Clear and Concise: Unambiguous language.
- Complete: Collectively, ACs should cover the scope of the task.
- User-Focused (where applicable): Frame ACs from the perspective of the end-user or the system's external behavior.

    - *Good Example:* "- [ ] User can successfully log in with valid credentials."
    - *Good Example:* "- [ ] System processes 1000 requests per second without errors."
    - *Bad Example (Implementation Step):* "- [ ] Add a new function `handleLogin()` in `auth.ts`."

### Task file

Once a task is created it will be stored in `tasks/` directory as a Markdown file with the format
`task-<id> - <title>.md` (e.g. `task-42 - Add GraphQL resolver.md`).

### Additional task requirements

- Tasks must be **atomic** and **testable**. If a task is too large, break it down into smaller subtasks.
  Each task should represent a single unit of work that can be completed in a single PR.

- Never reference tasks that are to be done in the future or that are not yet created. You can only reference
  previous tasks (id < current task id).

- When creating multiple tasks, ensure they are **independent** and they do not depend on future tasks.   
  Example of wrong tasks splitting: task 1: "Add API endpoint for user data", task 2: "Define the user model and DB
  schema".  
  Example of correct tasks splitting: task 1: "Add system for handling API requests", task 2: "Add user model and DB
  schema", task 3: "Add API endpoint for user data".

## Example Task Anatomy

```markdown
# task‑42 - Add GraphQL resolver

## Description (the why)

Short, imperative explanation of the goal of the task and why it is needed.

## Acceptance Criteria (the what)

- [ ] Resolver returns correct data for happy path
- [ ] Error response matches REST
- [ ] P95 latency ≤ 50 ms under 100 RPS

## Implementation Plan (the how)

1. Research existing GraphQL resolver patterns
2. Implement basic resolver with error handling
3. Add performance monitoring
4. Write unit and integration tests
5. Benchmark performance under load

## Implementation Notes (only added after working on the task)

- Approach taken
- Features implemented or modified
- Technical decisions and trade-offs
- Modified or added files
```

## Implementing Tasks

Mandatory sections for every task:

- Implementation Plan: (The "how") Outline the steps to achieve the task. Because the implementation details may
  change after the task is created, the implementation notes must be added only after putting the task in progress
  and before starting working on the task.
- Implementation Notes: Document your approach, decisions, challenges, and any deviations from the plan. This
  section is added after you are done working on the task. It should summarize what you did and why you did it. Keep it
  concise but informative.

IMPORTANT: Do not implement anything else that deviates from the **Acceptance Criteria**. If you need to
implement something not in the AC, update the AC first and then implement it or create a new task for it.

## Definition of Done 

A task is Done only when ALL the following are complete:

1. **Acceptance criteria** checklist in the task file is fully checked (all `- [ ]` changed to `- [x]`).
2. **Implementation plan** was followed or deviations were documented in Implementation Notes.
3. **Automated tests** (unit and integration) cover new logic.
4. **Static analysis**: linter & formatter succeed.
5. **Documentation**:
    - All relevant docs updated (any relevant README file, doc, etc.).
    - Task file **MUST** have an `## Implementation Notes` section added summarizing:
        - Approach taken
        - Features implemented or modified
        - Technical decisions and trade-offs
        - Modified or added files
6. **Review**: self review code.
7. **Task hygiene**: status set to **Done**.

IMPORTANT Never mark a task as Done without completing ALL items above.

