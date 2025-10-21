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

**Clone the repository:**

```bash
git clone https://github.com/int08h/roughenough.git
cd roughenough
```

**Build the project:**

```bash
# Build all workspace crates
cargo build

# Build with all optional features
cargo build --all-features

# Build release version
cargo build --release
```

**Verify your setup:**

```bash
# Run all tests
cargo test

# Run integration test on debug+release builds
cargo build && cargo build --release && target/debug/roughenough_integration_test

# Run checks
cargo check
cargo clippy
cargo +nightly fmt --check
```

## Development Workflow

## Project Structure

- **crates/roughenough-protocol**: Core wire format, request/response types, TLV encoding
- **crates/roughenough-merkle**: Merkle tree with Roughtime-specific tweaks
- **crates/roughenough-server**: Asynchronous UDP server with batching
- **crates/roughenough-client**: Command-line client and library
- **crates/roughenough-common**: Shared cryptography and encoding utilities
- **crates/roughenough-keys**: Key material handling with multiple secure backends
- **crates/roughenough-reporting-server**: Malfeasance report collection server
- **crates/roughenough-integration**: End-to-end integration tests
- **fuzz**: Fuzzing harness (separate crate, requires nightly)
- **doc/**: Protocol documentation and implementation guides
- **tasks/**: Project management and task tracking

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p roughenough-protocol
cargo test -p roughenough-merkle

# Run integration tests
cargo build
target/debug/roughenough_integration_test

# Run tests with all features enabled
cargo test --all-features
```

### Benchmarking

When making performance-critical changes, always benchmark before and after:

```bash
# Run all benchmarks
cargo bench

# Running benchmarks for specific crates
cargo bench -p roughenough-merkle
cargo bench -p roughenough-server
```

**Important:** Use benchmarks to validate performance improvements. Be skeptical of assumptions - measure actual 
performance with representative workloads. Please include benchmark results in your PR.

### Code Coverage

```bash
# Install cargo-llvm-cov (one time)
cargo install cargo-llvm-cov

# Generate HTML coverage report
./coverage.sh

# Generate lcov format for CI
./coverage.sh --lcov

# Coverage for specific crate
cargo llvm-cov -p roughenough-protocol --html
```

### Fuzzing

Fuzzing requires nightly Rust and is currently experimental:

```bash
# Switch to fuzzing crate
cd fuzz

# List available fuzz targets
cargo +nightly fuzz list

# Run fuzzing
cargo +nightly fuzz run fuzz_request_parse
cargo +nightly fuzz run fuzz_response_parse
cargo +nightly fuzz run fuzz_structured

# Minimize corpus after finding issues
cargo +nightly fuzz cmin <target>

# Analyze a crash
cargo +nightly fuzz run <target> <path-to-crash-artifact>
```

## Coding Standards

### Rust Style Guide

- Follow the official [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/)
- Use `cargo +nightly fmt` to format code (requires nightly toolchain)
- Run `cargo clippy` and address all warnings

### Unsafe Code Policy

**Roughenough maintains a no-unsafe policy.** Use `#![forbid(unsafe_code)]`.

**Exceptions:**
- The `server` crate implements `unsafe impl Send/Sync` on its `KeySource` type for manual thread safety
- The `client` binary (`main.rs`) uses unsafe for system clock manipulation via `libc::clock_settime`

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
   - Ensure all tests pass: `cargo test`
   - Ensure no clippy warnings: `cargo clippy`
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

