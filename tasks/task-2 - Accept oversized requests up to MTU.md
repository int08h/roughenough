# task-2 - Accept oversized requests up to MTU

Status: Done

## Description (the why)

The server currently rejects any UDP request that is not exactly 1024 bytes.
RFC 5.1 only requires that requests be at least 1024 bytes; future protocol
revisions or clients may legitimately send larger requests (more offered
versions, additional tags). Accepting requests up to a full non-fragmented
Ethernet MTU payload (1472 bytes = 1500 - 20 IP - 8 UDP) improves
interoperability while preserving the anti-amplification property, since
responses never exceed 1024 bytes. Requests smaller than 1024 bytes remain
rejected. Adapted from upstream PR #98; server-side only, the bundled client
continues to send exactly 1024-byte requests.

## Acceptance Criteria (the what)

- [x] A well-formed request between 1024 and 1472 bytes (inclusive) receives a
      valid response
- [x] Requests smaller than 1024 bytes are still rejected and counted as runts
- [x] Message parsing is bounded by the declared frame length: bytes trailing
      the declared length do not alter parsed tag values
- [x] Responses remain no larger than the requests they answer (RFC 5.1
      anti-amplification requirement)
- [x] Metrics distinguish oversized-but-accepted datagrams from rejected ones
- [x] Existing exact-1024-byte client requests see no behavior change

## Implementation Plan (the how)

1. Add MAX_REQUEST_SIZE = 1472 to protocol request.rs; relax
   Request::from_wire size check from exactly 1012 bytes to at least 1012
   bytes; update the BadRequestSize error message.
2. Add ParseCursor::truncate_remaining and call it from
   FromFrame::from_frame so parsing is bounded by the declared frame length.
3. Server collect_request: keep the runt rejection, count datagrams larger
   than 1024 bytes (renamed metric num_oversized_requests) and process them
   instead of rejecting.
4. Grow the server receive buffer from 1024 to MAX_REQUEST_SIZE (imported so
   the constants cannot drift).
5. Update metrics types/snapshot/aggregator for the renamed metric semantics.
6. Tests: protocol-level parse tests for 1011/1460-byte bodies and truncation
   equivalence, adversarial test for declared-length-bounded parsing, server
   tests for oversized-valid, oversized-garbage, and runt datagrams.

## Implementation Notes (only added after working on the task)

- Approach followed the plan. `Request::from_wire` now rejects only messages
  smaller than `REQUEST_SIZE - FRAME_OVERHEAD` (1012) bytes; the
  `BadRequestSize` error message was updated to match. `MAX_REQUEST_SIZE =
  1472` lives in protocol `request.rs` and the server's
  `NetworkHandler::RECV_BUFFER_SIZE` references it directly so the two cannot
  drift. Datagrams above 1472 are truncated by the OS; their declared frame
  length then exceeds the received bytes and parsing fails (`BufferTooSmall`
  -> counted as bad), which is the intended behavior.
- Parsing is bounded by the declared frame length: `FromFrame::from_frame`
  truncates the cursor to the declared length via the new
  `ParseCursor::truncate_remaining`. Without this, `RawHeader` (which uses the
  cursor's remaining bytes as the message length) would count trailing
  datagram bytes toward the final tag's value and validate header offsets
  against a too-large bound.
- Metric semantics changed: `num_jumbo_requests` (rejected) became
  `num_oversized_requests` (received datagrams > 1024 bytes that proceed to
  parsing). It was removed from the dropped/total sums in
  `metrics/snapshot.rs` and `examples/metrics_watcher.rs` because such
  requests are now also counted as ok or bad; the aggregator log line says
  "oversized=" instead of "jumbo=".
- Verified end to end against a live server: a hand-built 1472-byte request
  offering only draft version 0x8000000b received a 420-byte validated
  response (response <= request, RFC 5.1 anti-amplification holds; the
  response buffer remains 1024 bytes and responses cannot exceed the 1024-byte
  minimum request size).
- Benchmarks (divan, median) unchanged vs pre-change baseline: batch 64
  69.45us -> 68.87us, mixed-version 64 74.45us -> 74.40us.
- Modified files: protocol/src/{request.rs,error.rs,cursor.rs,wire.rs},
  protocol/tests/adversarial_request_tests.rs,
  server/src/{requests.rs,network.rs,metrics/{types,snapshot,aggregator}.rs},
  server/examples/metrics_watcher.rs.
