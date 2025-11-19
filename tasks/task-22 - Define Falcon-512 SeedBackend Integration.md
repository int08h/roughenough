# task-22 - Define Falcon-512-padded Backend Integration

## Description

Design how Falcon-512-padded private key material integrates with the existing SecretBackend trait architecture (renamed from SeedBackend to better reflect both seeds and keys). Unlike Ed25519 which uses a 32-byte seed, Falcon-512-padded uses a full private key structure. The solution must maintain consistency with current Ed25519 protection strategies while accommodating Falcon-512-padded's different key format, and provide a clear migration path for existing deployments.

**Dependencies**: Must complete before Task 25 (SecretBackend implementation).

## Acceptance Criteria

- [ ] Decision documented: Extend SecretBackend with algorithm-agnostic API (renamed from SeedBackend to reflect both seeds and keys)
- [ ] Approach: Add `sign_falcon(&mut self, data: &[u8]) -> Result<[u8; 666], BackendError>` method with default implementation returning NotSupported
- [ ] Approach justified: Maintains backwards compatibility, type safety, and ergonomic API while clearly reflecting the dual paradigm (seeds for Ed25519, keys for Falcon-512-padded)
- [ ] Falcon-512-padded key sizes documented from pqcrypto-falcon (NOT a seed - Falcon uses full key structures):
  - Private key: 1281 bytes
  - Public key: 897 bytes
  - Signature: 666 bytes (padded format)
- [ ] Private key storage format: Use same envelope encryption as Ed25519 seed (KMS/Secret Manager protect the Falcon private key)
- [ ] Backend compatibility matrix defined for v1.0:
  - Memory backend: YES (full support for testing/development)
  - Linux KRS: TBD (investigate keyring size limits for 1281-byte keys)
  - AWS KMS: NO (no PQ support yet)
  - GCP KMS: NO (no PQ support yet)
  - SSH agent: NO (protocol doesn't support 1281-byte keys)
  - PKCS11: NO (defer to future version)
- [ ] Migration path: How do existing servers add Falcon-512-padded capability without breaking Ed25519?
- [ ] Clarification: Ed25519 uses 32-byte seed → keypair derivation; Falcon-512-padded stores actual private key bytes
- [ ] Design document created: `doc/FALCON-BACKEND-INTEGRATION.md`
- [ ] Design reviewed against existing SecretBackend implementations
- [ ] Note: SecretBackend is more accurate name than SeedBackend since it handles both seed-based (Ed25519) and key-based (Falcon-512-padded) cryptographic material
