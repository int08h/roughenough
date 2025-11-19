# task-19.1 - Falcon-512 Implementation Steering

## Description

This steering task tracks the overall progress of adding Falcon-512-padded post-quantum signatures to Roughtime. It serves as a central checklist for the entire implementation, ensuring all prerequisite analysis, implementation, testing, and documentation tasks are completed in the correct order.

**CRITICAL**: Tasks must be completed in dependency order. Do not proceed with implementation tasks until all analysis tasks (20-22) are complete and show the approach is viable.

## Acceptance Criteria

### Analysis Phase (Must Complete First)
- [ ] Task 20: Analyze CERQ Response Size Constraints - BLOCKER: Must confirm approach is viable
- [ ] Task 21: Define Tag Values and Signing Domain - Security-critical specification (SIGQ and CERQ only, PUBQ removed as unused)
- [ ] Task 22: Define Falcon-512-padded SecretBackend Integration - Architectural design (renamed from SeedBackend)

### Implementation Phase - Protocol & Wire Format
- [ ] Task 23A: Add Falcon Tags to Protocol Enum (SIGQ and CERQ only, PUBQ removed)
- [ ] Task 23B: Implement SIGQ Wire Format (PUBQ removed as unused)
- [ ] Task 23C: Implement CERQ Tag Structure

### Implementation Phase - Key Management
- [ ] Task 24: Implement Falcon-512-padded Key Generation
- [ ] Task 25: Extend SecretBackend for Falcon-512-padded (renamed from SeedBackend)

### Implementation Phase - Server
- [ ] Task 26A: Implement Server CERQ Generation
- [ ] Task 26B: Add Server CERQ Tests

### Implementation Phase - Client
- [ ] Task 27A: Implement Client Falcon-512-padded Verification
- [ ] Task 27B: Integrate CERQ Validation in Client

### Testing & Validation
- [ ] Task 28: Add CERQ Integration Tests
- [ ] Task 29: Add Falcon-512-padded Test Vectors
- [ ] Task 30: Add Performance Benchmarks (measurement only, no threshold)
- [ ] Task 31: Add Edge Case Tests and Fuzzing

### Documentation
- [ ] Task 32: Update Documentation for PQ Support

### Final Validation
- [ ] All tests pass: `cargo test`
- [ ] All benchmarks run: `cargo bench`
- [ ] Fuzzing completed without crashes
- [ ] Documentation reviewed and complete
- [ ] Performance benchmarked and documented (measurement only, no specific threshold)
- [ ] Code formatted: `cargo +nightly fmt`
- [ ] Linter clean: `cargo clippy`
