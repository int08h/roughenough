# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please email **stuart@int08h.com** rather than opening a public issue.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

I'll respond when I can and work on a fix as time permits.

## Security Notes

### Cryptography
- Uses aws-lc-rs for Ed25519 signatures and SHA-512 hashing
- Follows Roughtime RFC specification (draft-ietf-ntp-roughtime-14)

### Key Protection
Online keys have multiple options for secure storage:
- Linux Kernel Retention Service (KRS)
- SSH agent
- PKCS#11 hardware 
- AWS KMS and Secrets Manager
- GCP KMS and Secrets Manager

See `doc/PROTECTION.md` for details.
