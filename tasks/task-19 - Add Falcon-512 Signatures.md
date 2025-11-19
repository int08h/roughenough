# task-19 - Add Falcon-512 Signatures

**STATUS: OBSOLETE - This task has been superseded by task-19.1 (Falcon-512 Implementation Steering) which breaks down the implementation into granular, testable subtasks (tasks 20-32).**

## Description

This task involves adding Falcon-512 post-quantum signatures to the existing codebase. 

## Acceptance Criteria

- [ ] Add Falcon-512-padded signatures to the codebase
- [ ] Use the pqcrypto-falcon crate
- [ ] Add a new tag "SIGQ" for Falcon-512-padded signatures
- [ ] Add a new CERQ tag that has both SIG Ed25519 and SIGQ Falcon-512-padded signatures
- [ ] The SIGQ signature in CERQ signs the bytes of the SIG and DELE values
- [ ] Update roughenough-protocol test cases to test CERQ
- [ ] The roughenough-server CLI has a flag that loads the Falcon-512-padded private key from a file
- [ ] When the roughenough-server CLI has the Falcon-512-padded private key flag, it generates CERQ instead of CERT 
- [ ] Tests in roughenough-server are updated for loading the Falcon-512-padded private key from a file
- [ ] Tests in roughenough-server are updated for CERQ

