---
id: task-5
title: Complete implementation of the keys cli subcommands
status: Done
assignee: []
created_date: '2025-07-24'
updated_date: '2025-07-24'
labels: []
dependencies: []
---

# task-5 - Complete implementation of the keys cli subcommands

## Description

Implement the Seal, Open, Store, and Get subcommands in the keys cli tool. The implementation will provide working
code for the handle_get(), handle_store(), handle_open(), and handle_seal() functions in keys.rs. Currently these
function bodies are simply `todo!()` placeholders. 

The Generate subcommand is already implemented and should be used as an example of the style/approach to be used
to implement the other subcommands. 

Little new code should be needed to complete this task. If you find a lot of code is being generated, stop and 
explain to the user why and ask for guidance.

## Acceptance Criteria

- [x] The Seal command is implemented in the `handle_seal` function
- [x] The Open command is implemented in the `handle_open` function
- [x] The Store command is implemented in the `handle_store` function
- [x] The Get command is implemented in the `handle_get` function
- [ ] All four commands are tested and working with GCP secret "projects/int08h-blog/secrets/roughenough-seed-test-1"
- [ ] All four commands are tesed and working with GCP kms key "projects/int08h-blog/locations/us-central1/keyRings/roughenough/cryptoKeys/roughenough-int08h"
- [x] Tests pass, code is formatted and 'clippy' clean

## Implementation Plan

1. Study the existing handle_generate function to understand the pattern
2. Implement handle_get to retrieve seeds from secret managers
3. Implement handle_store to save seeds to secret managers
4. Implement handle_open to decrypt envelope encrypted seeds
5. Implement handle_seal to envelope encrypt seeds
6. Test all functions with GCP Secret Manager and KMS
7. Run cargo check, clippy, and fmt to ensure code quality

## Implementation Notes

### Approach Taken
- Followed the pattern established in the `handle_generate` function for consistency
- Used the `storage` module's `try_load_seed` and `try_store_seed` functions which handle the prefixing and backend logic
- Implemented automatic prefix detection based on resource ID format (projects/... for GCP, arn:... for AWS)
- Added proper error handling with `tracing::error!` for all failure cases

### Features Implemented
- **handle_get**: Retrieves a seed from secret managers and outputs base64-encoded seed data
- **handle_store**: Reads seed data from input, validates it's 32 bytes, and stores in secret manager
- **handle_open**: Decrypts envelope encrypted seeds, with optional key override functionality
- **handle_seal**: Encrypts seeds with envelope encryption using KMS keys

### Technical Decisions
- Used BASE64_NOPAD encoding for seed data output to match the existing pattern
- Added automatic resource prefix detection to simplify user experience (no need to manually prefix with gcp-secret://, etc.)
- For handle_open, allowed key override to change the KMS key used for decryption
- All functions read from stdin or file and write to stdout or file, following Unix philosophy

### Modified Files
- `crates/keys/bin/keys.rs`: Implemented all four handle_* functions
