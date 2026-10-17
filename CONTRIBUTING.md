# Contributing to Roughenough

Thank you for your interest in contributing to Roughenough! This document provides guidelines and instructions 
for contributing to the project.

## Getting Started

### Development Environment Setup

**Prerequisites:**
- Rust toolchain; Roughenough targets stable Rust
- Linux, MacOS, or other Unix-like operating system
- Git
- Optional: cloud provider credentials for KMS feature development (AWS, GCP)
- Follow the [AI policy](AI_POLICY.md)

**Clone the repository:**

```bash
git clone https://github.com/int08h/roughenough.git
cd roughenough
```

**Build the project:**

```bash
# Build the default members (every crate except reporting-server)
cargo build

# Build every crate, including reporting-server
cargo build --workspace

# Build release version
cargo build --release
```

**Verify your setup:**

```bash
# Run all tests
cargo test

# Run the end-to-end test against the debug build (add --release to both commands for release)
cargo build && cargo run --bin roughenough_integration_test

# Run the checks CI runs
cargo +nightly fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
```

## Project Structure

Cargo workspace with eight crates under `crates/`:

- **roughenough-protocol**: Core wire format, request/response types, tag definitions, TLV encoding
- **roughenough-merkle**: Merkle tree with Roughtime-specific leaf/node tweaks (SHA-512, first 32 bytes)
- **roughenough-server**: UDP server using mio, with request batching and Merkle tree signatures
- **roughenough-client**: Command-line client and library: output formatting, response validation, and
  optional malfeasance reporting (`reporting` feature)
- **roughenough-common**: Shared cryptography and encoding utilities, and the clock source
- **roughenough-keys**: Key material handling
  - Online seed backends: in-memory (default), Linux KRS (`online-linux-krs`), SSH agent
    (`online-ssh-agent`), and PKCS#11 (`online-pkcs11`)
  - Long-term seed protection through the `roughenough_keys` tool: AWS KMS and Secrets Manager
    (`longterm-aws`), and GCP KMS and Secret Manager (`longterm-gcp`)
- **roughenough-reporting-server**: Web server that collects malfeasance reports. Not a default member:
  `cargo build` and `cargo test` skip it; `-p roughenough-reporting-server` builds and tests it
- **roughenough-integration**: End-to-end harness (`roughenough_integration_test`) that runs the server and
  client binaries, and the load generator `roughenough_load_test`
- **fuzz**: Fuzz targets `fuzz-request-parse`, `fuzz-response-parse`, and `fuzz-structured` (excluded from the
  workspace, requires nightly)
- **doc/**: Protocol documentation and implementation guides

## Development Commands

### Building

```bash
cargo build                                                       # Default members (skips reporting-server)
cargo build --workspace                                           # Every crate, including reporting-server
cargo build -p roughenough-reporting-server                       # Reporting server only
cargo build --release -p roughenough-server --features release    # Server with every shipped feature
cargo build --release -p roughenough-client --features reporting  # Client with malfeasance reporting
```

### Running Tests

```bash
# Run all tests (default members)
cargo test

# Run tests for specific crate
cargo test -p roughenough-protocol
cargo test -p roughenough-reporting-server

# Run every test with all features enabled, as CI does (see the ssh-agent note below)
cargo test --workspace --all-features

# Run the end-to-end test of the server and client binaries from the same profile (debug, then release)
cargo build && cargo run --bin roughenough_integration_test
cargo build --release && cargo run --release --bin roughenough_integration_test

# Keys backends are feature-gated; check one combination (CI's Keys Feature Matrix checks each)
cargo check -p roughenough-keys --features longterm-aws
```

With `--all-features` (or `--features online-ssh-agent`), the ssh-agent backend tests need a running agent in
`SSH_AUTH_SOCK`. They remove every identity from that agent, so point `SSH_AUTH_SOCK` at a throwaway agent
(`eval "$(ssh-agent)"`), not your own.

### Code Quality

```bash
cargo +nightly fmt                                                  # Format (requires nightly)
cargo +nightly fmt --check                                          # Format check
cargo clippy --workspace --all-targets --all-features -- -D warnings  # Lint
cargo deny check                                                    # Advisories, bans, licenses, and sources
```

CI runs all four checks. `.pre-commit-config.yaml` runs the format check and clippy as git pre-commit hooks;
enable them with `pre-commit install`.

### Benchmarking

When making performance-critical changes, always benchmark before and after:

```bash
# Run all benchmarks
cargo bench

# Running benchmarks for specific crates (merkle, server, and protocol have benches)
cargo bench -p roughenough-merkle
cargo bench -p roughenough-server
cargo bench -p roughenough-protocol
```

**Important:** Use benchmarks to validate performance improvements. Be skeptical of assumptions - measure actual 
performance with representative workloads. Please include benchmark results in your PR.

### Code Coverage

```bash
cargo install cargo-llvm-cov                                            # once
cargo llvm-cov --workspace --all-features --open                        # HTML report, opens browser
cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info
cargo llvm-cov -p roughenough-protocol --html                           # one crate
cargo llvm-cov clean --workspace
```

`--all-features` runs the ssh-agent backend tests, which need a throwaway agent (see Running Tests).

### Fuzzing

Fuzzing requires nightly Rust and is currently experimental:

```bash
# Switch to fuzzing crate
cd fuzz

# List available fuzz targets
cargo +nightly fuzz list

# Run fuzzing
cargo +nightly fuzz run fuzz-request-parse
cargo +nightly fuzz run fuzz-response-parse
cargo +nightly fuzz run fuzz-structured

# Minimize corpus after finding issues
cargo +nightly fuzz cmin <target>

# Analyze a crash
cargo +nightly fuzz run <target> <path-to-crash-artifact>
```

### Running Binaries

```bash
cargo run --bin roughenough_server -- --insecure-zero-seed       # Server (testing only; production needs --seed-file)
cargo run --bin roughenough_client -- -h                         # Client (see --help for options)
cargo run -p roughenough-keys --bin roughenough_keys -- --help   # Keys tool
cargo run -p roughenough-reporting-server --bin roughenough_reporting_server  # Reporting server (port 3000)
cargo run --release --bin roughenough_load_test -- <host> <port> -n N -w W -f F  # Load generator
```

## Coding Standards

### Rust Style Guide

- Follow the official [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/)
- Use `cargo +nightly fmt` to format code (requires nightly toolchain)
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` and address all warnings

### Dependencies

Take dependency updates even when they need a newer Rust. When the CI step "Dependencies fit the declared
MSRV" fails, raise `rust-version` in the root `Cargo.toml` `[workspace.package]`, the MSRV line in `README.md`,
and the `Dockerfile` base image together.

### Unsafe Code Policy

**Roughenough maintains a minimal-unsafe policy.** Use `#![forbid(unsafe_code)]`.
The `protocol`, `common`, `merkle`, `client` (library), `reporting-server`, 
and `integration` crates all carry `#![forbid(unsafe_code)]`.

**Exceptions:**
- The `keys` crate has two unsafe uses:
  - `src/online/aws_lc_ed25519.rs`: FFI calls into AWS-LC for Ed25519 key derivation and signing.
  - `src/seed/sshagent.rs`: `unsafe impl Send for SshAgentBackend`; the ssh-agent client's 
    boxed transport is a `UnixStream` (or pipe on Windows), both of which are `Send`.
- The `server` crate has one unsafe usage: 
  - The Linux-only `mmsg` module in `src/network.rs`, which wraps the `libc::sendmmsg` syscall for batched
    response sends. 
- The `client` binary (`main.rs`) uses unsafe for system clock manipulation via `libc::clock_settime`.

**For new contributions:**
- Avoid introducing unsafe code
- If unsafe is necessary, provide the rationale in your PR
- Restrict unsafe code to the smallest possible scope and include comments explaining why the unsafe code is correct

### Testing

- Write tests for new functionality
- Maintain or improve code coverage
- Include both unit tests and integration tests where appropriate
- Test error cases, not just happy paths
- Never disable or ignore tests to make tests pass

## Pull Request Process

1. **Create a feature branch** from `master`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

2. **Make your changes:**
   - Write clear, focused commits
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure all tests pass: `cargo test --workspace --all-features`
   - Ensure no clippy warnings: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - Format code: `cargo +nightly fmt`

3. **Push your branch:**
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create a pull request:**
   - Use a clear, descriptive title
   - Describe what changes you made and why
   - Reference any related issues
   - Include test results if relevant
   - Note any breaking changes

5. **Code review:**
   - Address review feedback promptly
   - Keep discussions focused and professional
   - Update your PR based on feedback

6. **Merge:**
   - PRs require approval before merging
   - Keep your branch updated with master
   - Squash commits if requested

