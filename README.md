# Roughtime

[![Build Status](https://github.com/int08h/roughenough/actions/workflows/rust.yml/badge.svg)](https://github.com/int08h/roughenough/actions/workflows/rust.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)

Roughenough is an implementation of the [Roughtime (RFC 10049)](https://www.rfc-editor.org/info/rfc10049) 
secure time synchronization protocol. Roughenough provides both server and client components for cryptographically 
verifiable time synchronization.

## Features

- Full implementation of the Roughtime RFC 10049 specification
- Command-line client with multiple output formats and server validation
- Performance oriented batching UDP server 
- Clients can (optionally) report malfeasance to a remote server for analysis
- Multiple backends for secure key and identity protection (KMS, Secret Manager, Linux KRS, 
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

The server requires a long-term identity seed file to start. Pass its path
with `--seed-file` (or the `ROUGHENOUGH_SEED_FILE` environment variable). For testing
you can use `--insecure-zero-seed` to run with an all-zero seed.

On Unix-like systems the seed file needs to be a regular file (no symlinks) with
`0400` or `0600` file permissions.

The seed file can contain one of (usually obtained from `roughenough-keys`): 
* exactly 32 bytes of binary random data
* a base64 or hex encoded value (`seed://` )
* an AWS or GCP KMS envelope (`aws-kms://` or `gcp-kms://`)
* an AWS or GCP Secret Manager reference (`aws-secret://` or `gcp-secret://`)
  
Use the `roughenough-keys` tool to generate a seed and encrypt/wrap it with
a secret manager or KMS.

```bash
# Debug build, testing-only zero seed
cargo run --bin roughenough_server -- --insecure-zero-seed

# Generate a new mode-0600 raw seed file
(umask 077 && openssl rand -hex 32 > roughenough.seed)

# Release build with optimizations and a real seed file
cargo run --release --bin roughenough_server -- --seed-file roughenough.seed

# Run the server binary directly (a read-only file is sufficient)
target/release/roughenough_server --seed-file /run/secrets/roughenough.seed
```

The server will start listening for UDP requests on the default port (5319, assigned to Roughtime by IANA).

### Running the Client

Basic usage:

```bash
# Query a Roughtime server
cargo run --bin roughenough_client -- roughtime.int08h.com 5319

# Verify server public key
cargo run --bin roughenough_client -- roughtime.int08h.com 5319 -k <base64-or-hex-key>

# Multiple requests
cargo run --bin roughenough_client -- roughtime.int08h.com 5319 -n 10

# Verbose output
cargo run --bin roughenough_client -- roughtime.int08h.com 5319 -v

# Different time formats
cargo run --bin roughenough_client -- roughtime.int08h.com 5319 --epoch  # Unix timestamp
cargo run --bin roughenough_client -- roughtime.int08h.com 5319 --zulu   # ISO 8601 UTC
```

Offer draft version 0x8000000c as well as version 1 (see [Protocol Versions](#protocol-versions)):

```bash
cargo run --bin roughenough_client -- roughtime.example.com 2002 -P both
```

Query multiple servers from an RFC compliant JSON list:

```bash
cargo run --bin roughenough_client -- -l servers.json
```

### Protocol Versions

The server answers only Roughtime version 1 (RFC 10049) and ignores requests
that do not offer it. Version 1 signatures use the RFC 10049 context strings,
`"Roughtime v1 response signature"` and `"Roughtime v1 delegation signature"`.

The client offers version 1 by default. `-P both` offers version 1 and draft
version 0x8000000c, and `-P 19` offers only the draft version. Draft responses
are verified with the draft context strings (`"RoughTime v1 ..."`).

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p roughenough-protocol

# Run integration tests
target/debug/roughenough_integration_test
```

## Project Structure

Roughtime is structured as a Cargo workspace with multiple crates:

- **protocol** - Core wire format handling, request/response types, data structures
- **merkle** - Merkle tree implementation with Roughtime-specific tweaks
- **server** - High-performance UDP server with async I/O and batching
- **client** - Command-line client for querying Roughtime servers
- **common** - Shared cryptography and encoding utilities
- **keys** - Key material handling with multiple secure storage backends
- **reporting-server** - Web server for collecting malfeasance reports
- **integration** - End-to-end integration tests
- **fuzz** - Fuzzing harness

## Optional Features

### Client Features

- **reporting** - Enables clients to report malfeasance to a remote server
  ```bash
  cargo build -p roughenough-client --features reporting
  cargo run --bin roughenough_client -- hostname.com 5319 --report
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

Thank you to all past and present contributors:

* Stuart Stock (stuart {at} int08h.com)
* Aaron Hill (aa1ronham {at} gmail.com)
* Peter Todd (pete {at} petertodd.org)
* Muncan90 (github.com/muncan90)
* Zicklag (github.com/zicklag)
* Greg at Unrelenting Tech (github.com/unrelentingtech)
* Eric Swanson (github.com/lachesis)
* Marcus Dansarie (github.com/dansarie)
* Marco Davids (github.com/mdavids)
* Tanner Ryan (github.com/tannerryan)

## License

Copyright (c) 2025-2026 the Roughenough Project Contributors.

Roughenough is licensed under either of

* [Apache License, Version 2.0](LICENSE-APACHE) (http://www.apache.org/licenses/LICENSE-2.0)
* [MIT License](LICENSE-MIT) (http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, 
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
