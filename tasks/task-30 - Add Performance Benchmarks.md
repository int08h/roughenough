# task-30 - Add Performance Benchmarks

## Description

Measure Falcon-512-padded performance impact to quantify the overhead and inform deployment decisions. Benchmarks must be run before and after implementation to provide accurate measurements. This task is measurement-only; no specific threshold is required for acceptance.

**Dependencies**: Requires Tasks 26A (Server CERQ), 27B (Client integration), 28 (Integration tests) complete.

## Acceptance Criteria

- [ ] Baseline benchmarks run BEFORE Falcon-512-padded implementation:
  - Ed25519 signing rate (signs/sec)
  - CERT generation time (microseconds)
  - Client CERT verification time (microseconds)
  - Server throughput with CERT (requests/sec)
- [ ] Baseline results documented in `doc/benchmarks/baseline-ed25519.md`
- [ ] Benchmark `falcon_signing_rate()` added to roughenough-keys/benches/
- [ ] Benchmark `cerq_generation_overhead()` added to roughenough-server/benches/
- [ ] Benchmark `cerq_verification_time()` added to roughenough-client/benches/
- [ ] Benchmark `server_throughput_with_cerq()` added to roughenough-server/benches/
- [ ] All benchmarks run: `cargo bench -p roughenough-keys -p roughenough-server -p roughenough-client`
- [ ] Results compared to baseline with percentage delta calculated
- [ ] Performance measurements documented (no specific threshold required)
- [ ] Results documented in `doc/benchmarks/falcon512-padded-performance.md` with analysis and commentary
- [ ] If significant degradation observed: Document potential mitigation strategies for future optimization
