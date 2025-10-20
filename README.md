# Roughtime

[![Build Status](https://github.com/int08h/roughenough/actions/workflows/rust.yml/badge.svg)](https://github.com/int08h/roughenough/actions/workflows/rust.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)

Roughenough is an implementation of the [IETF Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/) 
secure time synchronization protocol. Roughenough provides both server and client components for cryptographically 
verifiable time synchronization.

## Features

- **RFC Compliant**: Full implementation of the Roughtime RFC specification
- **High Performance Server**: Performance oriented asynchronous UDP server 
- **Flexible Client**: Command-line client with multiple output formats and server validation
- **Malfeasance Reporting**: Clients can (optionally) report malfeasance to a remote server for analysis
- **Key Management**: Multiple backends for secure key and identity protection (KMS, Secret Manager, Linux KRS, 
  SSH agent, PKCS#11)

## Quick Start

### System Requirements

- MSRV 1.88, Rust 2024 edition 
- Linux, MacOS, or other Unix-like operating system
- Optional: cloud provider credentials for backend key storage

### Installation

Build all components:

```bash
cargo build --release
```

Build with all optional features:

```bash
# Enable all optional features
cargo build --release --all-features 
```

### Running the Server

```bash
# Debug build
cargo run --bin server

# Release build with optimizations
cargo run --release --bin server

# Run the server binary directly
target/release/server
```

The server will start listening for UDP requests on the default port (2002).

### Running the Client

Basic usage:

```bash
# Query a Roughtime server
cargo run --bin client -- roughtime.int08h.com 2002

# Verify server public key
cargo run --bin client -- roughtime.int08h.com 2002 -k <base64-or-hex-key>

# Multiple requests
cargo run --bin client -- roughtime.int08h.com 2002 -n 10

# Verbose output
cargo run --bin client -- roughtime.int08h.com 2002 -v

# Different time formats
cargo run --bin client -- roughtime.int08h.com 2002 --epoch  # Unix timestamp
cargo run --bin client -- roughtime.int08h.com 2002 --zulu   # ISO 8601 UTC
```

Query multiple servers from an RFC compliant JSON list:

```bash
cargo run --bin client -- -l servers.json
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p protocol

# Run integration tests
target/debug/integration-test
```

## Project Structure

Roughtime is structured as a Cargo workspace with multiple crates:

- **protocol**: Core wire format handling, request/response types, data structures
- **merkle**: Merkle tree implementation with Roughtime-specific tweaks
- **server**: High-performance UDP server with async I/O and batching
- **client**: Command-line client for querying Roughtime servers
- **common**: Shared cryptography and encoding utilities
- **keys**: Key material handling with multiple secure storage backends
- **reporting-server**: Web server for collecting malfeasance reports
- **integration**: End-to-end integration tests
- **fuzz**: Fuzzing harness

## Optional Features

### Client Features

- **reporting**: Enable clients to report malfeasance to a remote server
  ```bash
  cargo build -p client --features reporting
  cargo run --bin client -- hostname.com 2002 --report
  ```

### Keys Crate Features

See [doc/PROTECTION.md](doc/PROTECTION.md) for detailed information on seed protection strategies.

#### Runtime Protection (Online Key Backends)

- `online-linux-krs` (default): Store seed in Linux Kernel Keyring for runtime protection
- `online-ssh-agent` Use SSH agent for seed storage and signing operations
- `online-pkcs11` PKCS#11 hardware security module integration (Yubikey, HSM, etc)

#### Long-term Protection (Seed Storage)

- `longterm-aws-kms` AWS Key Management Service for seed encryption
- `longterm-gcp-kms` Google Cloud KMS for seed encryption
- `longterm-aws-secret-manager` AWS Secrets Manager for seed storage
- `longterm-gcp-secret-manager` Google Cloud Secret Manager for seed storage

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Copyright (c) 2025 the Roughenough Project Contributors.

Roughenough is licensed under either of

* [Apache License, Version 2.0](LICENSE-APACHE) (http://www.apache.org/licenses/LICENSE-2.0)
* [MIT License](LICENSE-MIT) (http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, 
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
