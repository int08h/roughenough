# Network I/O Benchmarking Guide

This document explains how to use the network I/O benchmarks to measure the performance impact of switching from mio to io_uring for UDP networking in the Roughtime server.

## Overview

The `server_network` benchmark measures actual server-side I/O performance by spawning a real server process and sending UDP requests over loopback. Client overhead is explicitly excluded from measurements to focus on server performance. This complements the `server_ops` benchmark which measures protocol logic in isolation.

### What Each Benchmark Measures

- **server_ops**: Protocol processing (parsing, crypto, Merkle trees) - CPU-bound operations
- **server_network**: Server-side network I/O (UDP recv/send, event loop, syscalls) - I/O-bound operations, **client overhead excluded**

### Key Features

- **Client overhead excluded**: Requests are pre-sent or sent from background threads; only server response time is measured
- **Detailed output**: Benchmarks output actual measurements (latency percentiles, throughput) not just summary statistics
- **Server-focused**: All timing measures server operations, not round-trip client-server-client time

For evaluating mio vs io_uring, you need `server_network` plus Linux `perf` tools.

## Prerequisites

```bash
# Build the server in release mode (required for benchmarks)
cargo build --release --bin roughenough_server

# Install perf tools (Linux only)
sudo apt-get install linux-tools-common linux-tools-generic
# or
sudo yum install perf
```

## Running the Benchmarks

### Basic Usage

```bash
# Run all network benchmarks
cargo bench -p roughenough-server server_network

# Run specific benchmark
cargo bench -p roughenough-server server_network::single_request_latency

# Save results to file for comparison
cargo bench -p roughenough-server server_network > baseline_mio.txt
```

### With Syscall Profiling

The most important metric for mio vs io_uring comparison is syscall count:

```bash
# Count all syscalls during benchmark
perf stat -e 'syscalls:sys_enter_*' \
    cargo bench -p roughenough-server server_network

# Focus on network syscalls
perf stat -e 'syscalls:sys_enter_recvfrom,syscalls:sys_enter_sendto,syscalls:sys_enter_epoll_wait' \
    cargo bench -p roughenough-server server_network

# After implementing io_uring, add io_uring syscalls
perf stat -e 'syscalls:sys_enter_recvfrom,syscalls:sys_enter_sendto,syscalls:sys_enter_io_uring_enter' \
    cargo bench -p roughenough-server server_network
```

### With CPU Profiling

Measure CPU efficiency (cycles and instructions per request):

```bash
# CPU cycles, instructions, cache performance
perf stat -e cycles,instructions,cache-references,cache-misses \
    cargo bench -p roughenough-server server_network

# Include context switches (should be lower with io_uring)
perf stat -e cycles,instructions,context-switches \
    cargo bench -p roughenough-server server_network
```

## Benchmark Descriptions

### server_response_time

Measures server response time with client overhead excluded.

**What it tests:**
- Server processing time (excludes client send overhead)
- Event loop responsiveness
- Server-side syscall overhead per request

**Expected io_uring impact:** Minimal on loopback, more significant on real networks

### batch_requests (8, 16, 32, 64)

Pre-sends batches of requests, then measures only server response reception time.

**What it tests:**
- Server's batching efficiency (client send overhead excluded)
- How well the I/O layer handles multiple concurrent operations
- Syscall amortization across batch
- Server-side processing throughput

**Expected io_uring impact:** Moderate (10-30% improvement), especially at larger batch sizes

### latency_distribution

Pre-sends 1000 requests and measures server response times to compute percentiles (P50, P95, P99, P999).

**What it tests:**
- Server-side tail latency characteristics (client overhead excluded)
- Latency stability under load
- Worst-case server performance
- **Outputs:** Detailed percentile measurements for each benchmark run

**Expected io_uring impact:** Lower tail latencies due to more predictable syscall behavior

### server_throughput

Floods server with requests from background thread, measures only response reception rate.

**What it tests:**
- Maximum server processing throughput (responses/second)
- Server I/O layer scalability
- Server resource utilization efficiency
- **Outputs:** Responses received, duration, and throughput (responses/sec)

**Expected io_uring impact:** Higher maximum throughput (10-30% on loopback, more on real networks)

## Interpreting Results

### Baseline Measurements (Before io_uring)

Example baseline output:

```
server_network::server_response_time       fastest       slowest       median        mean
                                           40.4 us       17.3 ms       49.1 us       238 us

server_network::batch_requests/64          fastest       slowest       median        mean
                                           163.6 us      494.8 us      206 us        223 us

server_network::latency_distribution
Latency Distribution (server response time):
  P50:  9.738µs
  P95:  10.279µs
  P99:  11.752µs
  P999: 55.885µs

server_network::server_throughput
Server Throughput:
  Responses received: 190275
  Duration: 500.055142ms
  Throughput: 380508 responses/sec

perf stat output:
  Performance counter stats:
    12,456 syscalls:sys_enter_recvfrom
    12,456 syscalls:sys_enter_sendto
     8,234 syscalls:sys_enter_epoll_wait
```

### Expected Changes with io_uring

| Metric | Expected Change | Why |
|--------|----------------|-----|
| Syscall count | -50% to -90% | io_uring batches operations |
| Throughput | +10% to +30% | Reduced syscall overhead |
| Latency (median) | Minimal change | Loopback already very fast |
| Latency (P99/P999) | -10% to -30% | More predictable I/O |
| CPU cycles/request | -20% to -40% | Fewer kernel transitions |
| Context switches | -30% to -50% | Better async coordination |

### What "Good" Results Look Like

**Good io_uring implementation:**
```
Syscalls before:     12,456 recvfrom + 12,456 sendto + 8,234 epoll_wait = 33,146
Syscalls after:       2,341 io_uring_enter = -93% reduction

Throughput before:   25,000 req/s
Throughput after:    32,500 req/s = +30% improvement

CPU cycles/req:      -35% reduction
```

**Marginal io_uring implementation:**
```
Syscalls before:     33,146
Syscalls after:      28,912 = only -13% reduction (not utilizing batching well)

Throughput before:   25,000 req/s
Throughput after:    26,250 req/s = only +5% improvement
```

## Limitations and Caveats

### Loopback Networking

The benchmarks use `127.0.0.1` which has important limitations:

1. **No real network latency**: Packets never leave the host
2. **Kernel shortcuts**: Linux optimizes loopback differently than real interfaces
3. **Cache effects**: Data stays in CPU cache, hiding memory access patterns
4. **No packet loss**: Can't test io_uring's handling of retransmissions

**Impact:** io_uring's benefits are understated. Real networks will show larger improvements.

### Coordinated Omission

The `single_request_latency` and `batch_requests` benchmarks wait for responses before sending
new requests. This is appropriate for measuring latency but understates throughput potential.

The `sustained_throughput` benchmark uses separate threads to avoid this problem.

### Statistical Significance

For reliable comparisons:

```bash
# Run multiple times and compare distributions
for i in {1..5}; do
    cargo bench -p roughenough-server server_network > run_$i.txt
done

# Look for consistent patterns across runs
```

### Server Configuration

The benchmarks use default server settings:
- Port 2003
- Batch size 64
- Single thread

For production evaluation, test with your actual configuration:

```bash
# Start server with custom settings
./target/release/roughenough_server --num-threads 4 --batch-size 128 &

# Then run client-side of benchmark manually (would need custom script)
```

## Comparison Workflow

### Step 1: Establish Baseline (Current mio Implementation)

```bash
# Build current implementation
cargo build --release --bin roughenough_server

# Run benchmarks with profiling
perf stat -e cycles,instructions,syscalls:sys_enter_recvfrom,syscalls:sys_enter_sendto,syscalls:sys_enter_epoll_wait \
    cargo bench -p roughenough-server server_network > baseline_mio.txt 2> baseline_mio_perf.txt

# Save the output
git add baseline_mio*.txt
git commit -m "Baseline network performance before io_uring"
```

### Step 2: Implement io_uring

(Make your io_uring changes to the server)

### Step 3: Measure io_uring Performance

```bash
# Build io_uring implementation
cargo build --release --bin roughenough_server

# Run same benchmarks
perf stat -e cycles,instructions,syscalls:sys_enter_io_uring_enter \
    cargo bench -p roughenough-server server_network > io_uring.txt 2> io_uring_perf.txt
```

### Step 4: Compare Results

```bash
# Textual comparison
diff -u baseline_mio.txt io_uring.txt

# Or use a benchmarking comparison tool
# (divan outputs can be compared directly)
```

### Step 5: Analyze

Key questions to answer:

1. **Did syscalls decrease?** Look at perf output. Expect 50-90% reduction.
2. **Did throughput increase?** Look at sustained_throughput results. Expect 10-30%.
3. **Did latency improve?** Look at P99/P999 in latency_distribution.
4. **Was CPU efficiency better?** Look at cycles and instructions per benchmark iteration.

If any answer is "no", investigate why. The io_uring implementation may not be optimal.

## Troubleshooting

### Server Fails to Start

```
Error: Failed to spawn server. Did you run `cargo build --release`?
```

**Solution:** Build the server first:
```bash
cargo build --release --bin roughenough_server
```

### Timeouts During Benchmarks

```
Error: Failed to receive response
```

**Causes:**
- Server crashed (check with `ps aux | grep roughenough`)
- Port conflict (another server already running on 2003)
- Firewall blocking loopback (unlikely but possible)

**Solution:**
```bash
# Kill any existing servers
pkill roughenough_server

# Check port availability
netstat -tuln | grep 2003

# Run integration test to verify server works
cargo run --bin roughenough_integration_test
```

### Inconsistent Results

Benchmarks vary significantly between runs.

**Causes:**
- System load (other processes)
- CPU frequency scaling
- Thermal throttling

**Solution:**
```bash
# Reduce system noise
sudo systemctl stop <unnecessary-services>

# Disable CPU frequency scaling
sudo cpupower frequency-set --governor performance

# Run benchmarks multiple times and look for trends
```

### perf Permission Denied

```
Error: perf_event_open(...) failed: Permission denied
```

**Solution:**
```bash
# Temporarily allow perf for non-root
sudo sysctl -w kernel.perf_event_paranoid=-1

# Or run with sudo
sudo perf stat ...
```

## Advanced Usage

### Custom Benchmark Duration

```bash
# Run benchmarks longer for more stable results
DIVAN_MAX_TIME=30 cargo bench -p roughenough-server server_network
```

### Profiling with FlameGraphs

```bash
# Collect profile data
perf record -F 99 -g -- cargo bench -p roughenough-server server_network

# Generate flamegraph
perf script | stackcollapse-perf.pl | flamegraph.pl > benchmark_profile.svg
```

### Testing on Real Network Interface

Modify the benchmark source to use a real interface instead of loopback:

```rust
// In server_network.rs, change:
let socket = UdpSocket::bind("127.0.0.1:0")  // loopback
// To:
let socket = UdpSocket::bind("192.168.1.100:0")  // real interface

// And point to server on different machine:
let server_addr = "192.168.1.101:2003"
```

## Additional Resources

- [Roughtime RFC](doc/draft-ietf-ntp-roughtime-14.txt) - Protocol specification
- [io_uring documentation](https://kernel.dk/io_uring.pdf) - Kernel feature details
- [perf tutorial](https://perf.wiki.kernel.org/index.php/Tutorial) - Performance profiling
- [divan documentation](https://docs.rs/divan) - Benchmark framework

## Summary

For evaluating io_uring's impact:

1. **Run benchmarks before and after** with identical conditions
2. **Focus on syscall counts** (via perf) as primary metric
3. **Expect 50-90% syscall reduction** with well-implemented io_uring
4. **Expect 10-30% throughput improvement** on loopback (more on real networks)
5. **Use multiple runs** to establish statistical significance
6. **Combine benchmark results with perf profiling** for complete picture

The benchmarks are a starting point. Real-world production testing with actual traffic patterns
is essential for final validation.
