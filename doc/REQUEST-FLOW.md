# Request/Response Flow

End-to-end flow of a single Roughtime exchange. Function names
reference the code; see `doc/RFC-PROTOCOL.md` for the wire format and
`doc/draft-ietf-ntp-roughtime-*.txt` for the spec.

## Overview

- The server runs N worker threads, each owning its own UDP socket via
  `SO_REUSEPORT`; we lean on the kernel to load-balance datagrams across them. 
  No shared state or allocations on the hot path.
- Each worker drains batches of requests, commits them all to a single Merkle
  tree, signs once per distinct protocol version, and emits one response per
  request (differing only in PATH, NONC, INDX across responses in a batch).
- The client reconstructs the Merkle root from its own request and walks the 
  signature chain back to the server's long-term key, which it knows
  out-of-band.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant Sock as UDP Socket
    box Server worker thread
        participant W as Worker::run
        participant N as NetworkHandler
        participant RH as RequestHandler
        participant RS as ResponseHandler
        participant K as OnlineKey
        participant M as MerkleTree
    end

    Note over C: ClientBuilder::build -> create_request
    C->>Sock: send framed Request<br/>(ROUGHTIM | len | VER NONC TYPE [SRV] ZZZZ)

    loop event loop (mio poll, 350ms)
        Sock-->>W: READABLE event
        loop drain up to batch_size datagrams
            W->>N: collect_requests(sock)
            N->>Sock: recv_from
            Sock-->>N: datagram bytes
            N->>RH: collect_request(bytes, src_addr)
            Note over RH: size gate (>=1024)<br/>Request::from_frame parse<br/>SRV check (RFC 5.2)<br/>version negotiate (RFC 5.1.1)
            RH->>RS: add_request(bytes, request, version, addr)
            RS->>M: push_leaf(request_bytes)
        end

        W->>RH: generate_responses(callback)
        RH->>RS: process_responses(callback)
        RS->>M: compute_root()
        M-->>RS: root_hash (one per batch)
        loop per distinct version in batch
            RS->>K: make_srep(version, root)
            Note over K: SREP = {VER, RADI, MIDP, VERS, ROOT}<br/>sign(srep_prefix || SREP)
            K-->>RS: (SREP, SIG) template + CERT
        end
        loop per pending request
            RS->>M: get_paths_to(index)
            M-->>RS: Merkle path (siblings)
            Note over RS: clone version template<br/>set PATH, NONC, INDX<br/>Response::to_frame
            RS->>N: callback(addr, response_bytes)
            N->>Sock: send_to(response, addr)
            Sock-->>C: framed Response
        end
    end

    Note over C: ResponseValidator::validate (RFC 5.4)
    C->>C: check_dele_signature<br/>(long-term key signed DELE)
    C->>C: check_midpoint<br/>(MINT <= MIDP <= MAXT)
    C->>C: check_merkle_proof<br/>(root_from_paths(INDX, my_request, PATH) == ROOT)
    C->>C: check_srep_signature<br/>(DELE.PUBK signed SREP)
    Note over C: returns authenticated MIDP<br/>paired with RADI -> Measurement
```

## Trust chain verified by the client

```
long-term key --signs--> DELE (online key + [MINT,MAXT])
    DELE.PUBK --signs--> SREP (ROOT, MIDP, RADI)
         ROOT --commits--> Merkle tree --contains--> client's request (nonce)
```

## Code references

| Stage | Location |
|-------|----------|
| Worker event loop | `crates/roughenough-server/src/worker.rs` (`Worker::run`) |
| Datagram read | `crates/roughenough-server/src/network.rs` (`collect_requests`) |
| Parse + validate + negotiate | `crates/roughenough-server/src/requests.rs` (`collect_request`) |
| Frame/TLV decode | `crates/roughenough-protocol/src/{wire,request,header}.rs` |
| Batch staging | `crates/roughenough-server/src/responses.rs` (`add_request`) |
| Build responses | `crates/roughenough-server/src/responses.rs` (`process_responses`) |
| Sign SREP | `crates/roughenough-keys/src/online/onlinekey.rs` (`make_srep`) |
| Merkle root / path | `crates/roughenough-merkle/src/lib.rs` (`compute_root`, `get_paths_to`) |
| Client validation | `crates/roughenough-client/src/validation.rs` (`ResponseValidator::validate`) |
| Root reconstruction | `crates/roughenough-merkle/src/lib.rs` (`root_from_paths`) |
