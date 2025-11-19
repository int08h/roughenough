# task-32 - Update Documentation for PQ Support

## Description

Document the Falcon-512-padded architecture, usage instructions, security model, and migration guidance for operators and developers. Comprehensive documentation ensures successful deployment and maintenance.

**Dependencies**: Requires all implementation tasks (23A-31) complete.

## Acceptance Criteria

- [ ] `CLAUDE.md` updated with Falcon-512-padded overview in "Architecture" section:
  - Emphasize opt-in nature: default is RFC Ed25519-only
  - Document server behavior: CERT by default, CERQ when Falcon key provided
  - Document client behavior: CERT validation by default, CERQ validation when Falcon pubkey provided
- [ ] `doc/RFC-PROTOCOL.md` extended with:
  - Section 5.2.X: SIGQ tag specification (666 bytes, Falcon-512-padded signature)
  - Section 5.2.Y: PUBQ tag specification (897 bytes, Falcon-512-padded public key)
  - Section 5.2.Z: CERQ tag specification (optional extension to CERT for PQ-enabled servers)
  - Signing domain specification (exact bytes SIGQ signs per Task 21)
  - Clarify CERQ is an optional extension, not a replacement of RFC protocol
- [ ] `doc/PROTECTION.md` updated with Falcon-512-padded private key protection strategies
- [ ] Server `--help` documents optional flags:
  - `--falcon-key-backend <backend>` (optional - enables CERQ when provided)
  - `--falcon-private-key <hex>` (optional - enables CERQ when provided)
  - Clearly state: "Without Falcon flags, server uses RFC Ed25519-only protocol (CERT)"
- [ ] Client `--help` documents optional Falcon configuration:
  - `--falcon-pubkey <base64-or-hex>` flag (optional - enables CERQ validation)
  - JSON `falcon_public_key` field (optional)
  - Clearly state: "Without Falcon pubkey, client uses RFC Ed25519-only validation (CERT)"
- [ ] `README.md` updated with:
  - Post-quantum feature as optional extension
  - Default behavior: RFC-compliant Ed25519-only (unchanged)
  - Opt-in example: how to enable Falcon-512-padded on server and client
  - Migration guidance: can deploy incrementally, no breaking changes
- [ ] Code comments added in key files:
  - roughenough-protocol/src/tags/cerq.rs explaining CERQ structure and opt-in usage
  - roughenough-client/src/validation.rs explaining hybrid verification and default CERT behavior
  - roughenough-keys/src/longterm/identity.rs explaining SIGQ signing domain
  - roughenough-server: comment explaining CERT (default) vs CERQ (opt-in) selection logic
- [ ] All documentation uses consistent terminology (CERQ, SIGQ, PUBQ, Falcon-512-padded, hybrid signature, opt-in, RFC default)
- [ ] Clarify Ed25519 uses seed-derived keypairs while Falcon-512-padded uses private key directly
- [ ] Document protocol negotiation: no explicit negotiation, server mode determined by key configuration
- [ ] Document backwards compatibility guarantees: existing deployments unaffected by default
- [ ] Document protocol mismatch behavior and logging:
  - Client without Falcon key + CERQ → Accept with INFO log
  - Client with Falcon key + CERT → Reject with ERROR log
  - Rationale for asymmetric handling
- [ ] Document Falcon-512-padded key sizes:
  - Private key: 1281 bytes
  - Public key: 897 bytes
  - Signature: 666 bytes (padded)
- [ ] Document signing domain: Context prefix `b"RoughTime v1 CERQ\0"` used for SIGQ
- [ ] Migration guide with specific steps:
  1. Generate Falcon key pair on server
  2. Export Falcon public key (base64/hex)
  3. Start server with --falcon-key-backend flag
  4. Verify server logs show "Using Falcon-512-padded hybrid protocol (CERQ responses)"
  5. Test with non-Falcon client (should work - backwards compatible)
  6. Distribute Falcon public key to clients
  7. Update client configs with --falcon-pubkey flag
  8. Verify client logs show CERQ validation
  9. Monitor for SIGQ validation failures
