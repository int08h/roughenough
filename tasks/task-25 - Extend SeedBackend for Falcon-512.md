# task-25 - Extend SecretBackend for Falcon-512-padded

## Description

Implement the Falcon-512-padded integration strategy defined in Task 22, extending the SecretBackend trait (renamed from SeedBackend) to support dual-algorithm signing while maintaining backwards compatibility with existing Ed25519-only deployments.

**Dependencies**: Requires Tasks 22 (SecretBackend design) and 24 (Key generation) complete.

## Acceptance Criteria

- [ ] SecretBackend trait in `roughenough-keys/src/seed.rs` extended with:
  ```rust
  fn sign_falcon(&mut self, data: &[u8]) -> Result<[u8; 666], BackendError> {
      Err(BackendError::NotSupported("Falcon-512-padded not supported by this backend".to_string()))
  }
  ```
- [ ] MemoryBackend implements `sign_falcon()` using pqcrypto-falcon
- [ ] MemoryBackend stores both Ed25519 seed (32 bytes) and optional Falcon-512-padded private key (1281 bytes)
- [ ] LinuxKrsBackend implements `sign_falcon()` 
- [ ] KMS backends implement `sign_falcon()`
- [ ] Other backends (SSH-agent, PKCS11) return NotSupported error with clear message
- [ ] Test: `memory_backend_falcon_signing()` validates MemoryBackend falcon signature
- [ ] Test: `backend_without_falcon_returns_not_supported()` verifies error handling
- [ ] Documentation added explaining backend Falcon support matrix
- [ ] All tests pass: `cargo test -p roughenough-keys`
