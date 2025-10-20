# Fuzzing Infrastructure

This directory contains fuzz tests for the Roughtime protocol implementation.

## Prerequisites

Nightly Rust is required as these targets use libFuzzer.

Install cargo-fuzz:
```bash
cargo +nightly install cargo-fuzz
```

## Running Fuzz Tests

From the root of the project:

```bash
# Fuzz request parsing
cargo +nightly fuzz run fuzz_request_parse -- -max_len=1280

# Fuzz response parsing
cargo +nightly fuzz run fuzz_response_parse -- -max_len=800

# Structure-aware fuzzing of complex message types
cargo +nightly fuzz run fuzz_structured -- -max_len=1024
```

The different `-max_len` values constrain the inputs generated to bounds applicable to real-world roughtime protocol
usage. Otherwise the fuzzer wastes time on large inputs (up to 4096 bytes) that are always rejected in practice.

## Fuzz Targets

- **fuzz_request_parse**: Tests parsing of request messages including frame validation
- **fuzz_response_parse**: Tests parsing of response messages and accessing fields
- **fuzz_structured**: Structure-aware fuzzing for Request, Response, SREP, DELE, and CERT messages using the arbitrary crate

## Running with Specific Options

```bash
# Run for a specific duration
cargo +nightly fuzz run fuzz_request_parse -- -max_total_time=60

# Run with more threads
cargo +nightly fuzz run fuzz_request_parse -- -fork=4

# Run with a specific corpus
cargo +nightly fuzz run fuzz_request_parse corpus/
```

## Minimizing the Corpus

Run periodically for coverage-guided corpus minimization:

```bash
cargo +nightly fuzz cmin fuzz_request_parse
cargo +nightly fuzz cmin fuzz_response_parse
cargo +nightly fuzz cmin fuzz_structured
```

## Analyzing Crashes

If a crash is found, it will be saved in `fuzz/artifacts/`. To reproduce:

```bash
cargo +nightly fuzz run fuzz_request_parse fuzz/artifacts/fuzz_request_parse/crash-*
```
