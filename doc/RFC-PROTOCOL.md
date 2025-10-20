Roughtime Protocol Summary for AI

Core Protocol Overview

Roughtime is a cryptographic time synchronization protocol providing authenticated timestamps with proof of server malfeasance. It uses Ed25519 signatures and SHA-512 hashing (first 32 bytes).

Wire Format

- Packets: 8-byte magic 0x524f55474854494d ("ROUGHTIM" in ASCII), 4-byte length (LE), message body
- Requests: Must be exactly 1024 bytes total (pad with ZZZZ tag containing zeros)
- Responses: Variable size based on Merkle path length and VERS length
- Transport: UDP (single datagram) or TCP (multiple messages per connection)

Message Format (TLV)

- Header: N pairs count (uint32), N-1 offsets (uint32 array), N tags (uint32 array)
- Values section follows header at specified offsets
- Tags must be sorted numerically, offsets must be multiples of 4 and increasing
- All integers are little-endian

Request Tags

- VER: List of supported version numbers (sorted, unique)
- NONC: 32-byte random nonce
- TYPE: Must be 0 for requests
- SRV: Optional, H(0xff || server_pubkey) truncated to 32 bytes (H = SHA-512[0:32])
- ZZZZ: Padding zeros to reach 1024 bytes

Response Tags

- SIG: 64-byte Ed25519 signature over SREP
- NONC: Echo of request nonce
- TYPE: Must be 1 for responses
- PATH: Merkle tree path (32-byte hashes concatenated)
- INDX: Leaf index in Merkle tree (uint32)
- CERT: Contains DELE and SIG
- SREP: Signed response containing:
  - VER: Single version number
  - RADI: Accuracy radius in seconds (>=1, recommend >=3 for leap seconds)
  - MIDP: Timestamp (uint64 seconds since Unix epoch)
  - VERS: List of server's supported versions
  - ROOT: 32-byte Merkle tree root

Certificate Structure (CERT)

- DELE: Delegation certificate containing:
  - MINT: Minimum valid timestamp
  - MAXT: Maximum valid timestamp
  - PUBK: 32-byte Ed25519 public key
- SIG: Signature over DELE using long-term key

Merkle Tree

- Leaf nodes: H(0x00 || full_request_packet)
- Internal nodes: H(0x01 || left_child || right_child)
- H = SHA-512 truncated to first 32 bytes (SHA-512[0:32])
- PATH contains sibling hashes from leaf to root
- Maximum tree height should ensure PATH <= 32 hashes

Signature Contexts

- Response signature: "RoughTime v1 response signature\0"
- Delegation signature: "RoughTime v1 delegation signature\0"

Client Protocol

1. Send request with random nonce
2. Verify response signatures and Merkle path
3. For chaining: next_nonce = H(response_packet || 32_random_bytes)
4. Check causality: MIDP[i] - RADI[i] <= MIDP[j] + RADI[j] for i < j

Critical Implementation Notes

- Version 1 = 0x00000001 (draft uses 0x8000000c for testing)
- Tags are 4 ASCII chars padded with zeros, uppercase only
- Responses must not exceed request size (amplification prevention)
- Servers batch requests using Merkle trees for efficiency

