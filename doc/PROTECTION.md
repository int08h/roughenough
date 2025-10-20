# Long-Term Seed Protection

A 32-byte blob of uniformly random data is the "seed" used to derive the keys that form the server's long-term identity.
Protection of the seed is concerned with ensuring the plaintext seed bytes are never persisted (written to disk/storage)
in the clear, purposely or accidentally (a log file, for example).

Two approaches are available to protect the long-term seed:
1. The seed is stored in a remote secret manager service, or
2. A key management system (KMS) encrypts the seed value and the encrypted value is persistent locally.

At Roughenough server startup the seed is either: 1) retrieved from the secret manager, or 2) the seed is decrypted
by the KMS. Both approaches require interaction with an external service, but only at server startup.

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
