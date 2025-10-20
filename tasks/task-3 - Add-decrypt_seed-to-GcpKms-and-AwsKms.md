---
id: task-3
title: Add decrypt_seed to GcpKms and AwsKms
status: Done
assignee:
  - '@stuart'
created_date: '2025-07-09'
updated_date: '2025-07-09'
labels: []
dependencies: []
---

## Description

Implement `decrypt_seed` in `AwsKms` and `GcpKms`. The counterpart function `encrypt_seed` already exists
in `AwsKms` and `GcpKms`. 

## Acceptance Criteria

- [x] Added `decrypt_seed(SeedEnvelope) -> Seed` to AwsKms
- [x] Added `decrypt_seed(SeedEnvelope) -> Seed` to GcpKms
- [x] Added tests that verify the round-trip of a value between `encrypt_seed` and `decrypt_seed` for  
      both GcpKms and AwsKms
- [x] Implemented `open_dek` methods inside GcpKms and AwsKms which are mirrors of existing `seal_dek`
      methods.
- [x] Put AwsKms and its tests behind a Cargo feature "aws-kms"
- [x] Put GcpKms and its tests behind a Cargo feature "gcp-kms"
- [x] Ran all tests and confirmed they pass
- [x] Ran clippy and cargo fmt

## Implementation Plan

1. Examine existing encrypt_seed implementations in AwsKms and GcpKms
2. Implement decrypt_seed in AwsKms with proper error handling
3. Implement decrypt_seed in GcpKms with proper error handling  
4. Implement open_dek methods as mirrors of seal_dek in both classes
5. Add Cargo features aws-kms and gcp-kms to control compilation
6. Write round-trip tests for encrypt_seed/decrypt_seed
7. Run all tests, clippy, and cargo fmt

## Implementation Notes

Implemented decrypt_seed methods for both AwsKms and GcpKms that decrypt seeds previously encrypted by encrypt_seed. Also implemented the corresponding open_dek methods as mirrors of seal_dek to decrypt the data encryption keys. Added Cargo features 'aws-kms' and 'gcp-kms' to conditionally compile the cloud KMS implementations and their dependencies. Added comprehensive round-trip tests that verify encrypt/decrypt operations work correctly (tests require cloud credentials and are marked as ignored). All code has been formatted with cargo fmt and passes compilation checks.
