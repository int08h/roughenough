# Long-Term Seed Protection

A 32-byte blob of uniformly random data is the "seed" used to derive the keys that form the server's long-term identity.
Protection of the seed is concerned with ensuring the plaintext seed bytes are never persisted (written to disk/storage)
in the clear, purposely or accidentally (a log file, for example).

Two approaches are available to protect the long-term seed:
1. The seed is stored in a remote secret manager service, or
2. A key management system (KMS) encrypts the seed value and the encrypted value is persistent locally.

At Roughenough server startup the seed is either: 1) retrieved from the secret manager, or 2) the seed is decrypted
by the KMS. Both approaches require interaction with an external service, but only at server startup.

## Creating a protected seed file

The `roughenough_keys` tool writes a one-line seed file that the server loads with `--seed-file`. Build both with the
feature for your cloud: `cargo build --release -p roughenough-keys --features longterm-aws` (or `longterm-gcp`), and
the server with the same feature or with `--features release`, which includes both.

```bash
# Encrypt an existing seed file (hex, base64, or seed://) with a KMS key
roughenough_keys protect -i seed.txt --resource aws-kms://arn:aws:kms:... -o roughenough.seed

# Generate a new random seed and store it in a secret manager
roughenough_keys generate --resource gcp-secret://projects/P/secrets/S -o roughenough.seed

# Print the plain seed that a seed file refers to, as a seed:// value
roughenough_keys recover -i roughenough.seed
```

`--resource` accepts `aws-kms://<key ARN>`, `gcp-kms://<key name>`, `aws-secret://<secret ARN>`, and
`gcp-secret://<secret name>`. `protect` applies the server's seed-file checks to its input (no group or other access, no
symlinks), and also accepts an already protected seed file, which it re-protects under the new resource. `--json`
prints the envelope as pretty JSON instead; `recover` accepts either form. `recover --key` decrypts with a different
key id; an id without a scheme prefix, such as a bare ARN, keeps the envelope's scheme.

Output files are created with mode 0600 and never overwrite an existing file. Prefer `-o` over redirecting stdout for
`recover`, since its output is the plain seed. Every failure exits non-zero and prints nothing to stdout.

# Runtime Key Protection

The long-term identity signs generated online keys at runtime to create a chain-of-trust. Thus access to the long-term 
identity is needed **during runtime** to create new OnlineKeys. We don't want to introduce a dependency on a remote 
service like a secret manager or KMS in the request serving path.

The identity seed is kept outside the server's address space during server operation. This way a compromised
server process can't read the seed and an accident or bug can't leak it. The `KRS` and `ssh-agent` backends both store
the seed outside the server's address space.

When the seed is required (e.g. generating a new OnlineKey):

* The `KRS` backend retrieves the seed from kernel memory, the seed is used to sign a new OnlineKey, and the seed is
  then zeroized. In total, the seed is present very briefly (milliseconds) in the server's address space before it's
  overwritten.
* The `ssh-agent` backend makes an IPC call (over a Unix domain socket) to an `ssh-agent` process local to the server
  with the bytes to be signed and the `ssh-agent` does the signing. The seed contents are never present in the server's
  address space (precisely: not after startup, when the seed is loaded into the ssh-agent).

The `ssh-agent` backend is probably the more "secure" choice, however it introduces complexity by requiring operation
and maintenance of an `ssh-agent` process. The KRS backend has the benefit that "it just works" and is a good choice 
if running the server on Linux.

## PKCS#11 tokens

The `pkcs11` backend (`--seed-backend pkcs11`, in servers built with the `online-pkcs11` feature) signs with an
Ed25519 private key that already lives on a PKCS#11 token, such as an HSM or a YubiKey. There is no seed: the token
holds the long-term key, so the server takes no `--seed-file` (and rejects one, as well as `--insecure-zero-seed`).
The server uses the first Ed25519 private key it finds on the token and reads its public key once at startup.
Configure the token through environment variables:

* `ROUGHENOUGH_PKCS11_LIBRARY`: path to the PKCS#11 module library (required)
* `ROUGHENOUGH_PKCS11_SLOT`: index of the token slot (optional; defaults to 0)
* `ROUGHENOUGH_PKCS11_PIN`: user PIN for the token (required)
