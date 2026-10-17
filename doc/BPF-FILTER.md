# Linux BPF Request Filter

Notes for whoever tests or changes the classic BPF socket filter. CI runs
`bpf_filter_tests` on the GitHub Actions ubuntu runner.

## What it does

Each worker's UDP socket gets a classic BPF (cBPF) program through
`SO_ATTACH_FILTER`. The kernel runs it before queueing a datagram on the
socket and drops anything that cannot be a valid request:

| Check | Drops |
|---|---|
| UDP payload > `MAX_REQUEST_SIZE` (1472) | oversized and reassembled fragmented datagrams |
| UDP payload < `REQUEST_SIZE` (1024) | runts |
| first 8 payload bytes != `ROUGHTIM` | wrong protocol, reflected junk |

Dropped datagrams never take receive-buffer space, wake a worker, or cost
a `recv_from`. A flood of small packets can no longer fill the buffer and
crowd out real requests. The userspace checks in `network.rs` and
`requests.rs` are unchanged and remain authoritative.

## Where

- `crates/roughenough-server/src/filter.rs`: the program as a
  `PROGRAM` constant, `attach()` (Linux only, via
  `socket2::Socket::attach_filter`), and unit tests that run the program
  through a small cBPF interpreter on any platform.
- `crates/roughenough-server/src/main.rs`, `bind_socket`: attaches the
  filter before `bind`, so no datagram is queued unfiltered. If attaching
  fails, the server logs a warning and runs without the filter.
- `crates/roughenough-server/tests/bpf_filter_tests.rs`: Linux-only
  test. It sends invalid and valid datagrams to a filtered loopback socket
  over IPv4 and IPv6 and checks that only the valid ones arrive.

## UDP header assumption

On a UDP socket, the filter sees the 8-byte UDP header at offset 0, and
the packet length includes it (`UDP_HEADER_LEN` in `filter.rs`). This
matches `udp_queue_rcv_one_skb` and `udpv6_queue_rcv_one_skb`, which call
`sk_filter_trim_cap(sk, skb, sizeof(struct udphdr))` while `skb->data`
points at the UDP header. Confirmed by `bpf_filter_tests`; if that test
receives nothing at all on some kernel, the assumption does not hold there.

## What CI covers

The ubuntu CI jobs build and lint the Linux-only `attach` path and run the
filter unit tests and `bpf_filter_tests`.

## Testing on Linux

Run from the repository root:

```bash
cargo test -p roughenough-server --lib filter      # includes opcodes_match_libc
cargo test -p roughenough-server --test bpf_filter_tests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build && cargo run --bin roughenough_integration_test
```

To check a live server, start it and send runts and junk, then confirm
the kernel dropped them:

```bash
cargo run --bin roughenough_server -- --insecure-zero-seed -i 127.0.0.1 &
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(1000):
    s.sendto(b"x" * 100, ("127.0.0.1", 5319))          # runt
    s.sendto(b"JUNKJUNK" + b"\0" * 1016, ("127.0.0.1", 5319))  # bad magic
'
grep '^Udp:' /proc/net/snmp      # InErrors should rise by about 2000
cat /proc/net/udp                # the drops column for port 14C7 (5319)
cargo run --bin roughenough_client -- 127.0.0.1 5319   # still answered
```

Expected: the server's metrics log shows `runt=0` and `bad=0` for this
traffic, because these datagrams never reach userspace. Kernel counters
show the drops instead. The counter locations are inferred from kernel
source and still need confirming.

## Benchmarking (still needed)

AGENTS.md requires before-and-after measurements. The baseline is commit
`91e4890`, the commit before the filter. Run a runt flood from a separate
host or process while `roughenough_load_test` measures valid traffic:

```bash
cargo run --release --bin roughenough_load_test -- <host> <port> -n N -w W -f F
```

Compare the response rate and latency percentiles, never averages.
`ss -uam` shows receive-buffer use and drops per socket during the flood.
`roughenough_load_test` cannot send runts, so the flood needs its own tool.

## Metrics impact

On Linux, `num_runt_requests` and `num_oversized_dropped` stay near zero,
and `num_bad_requests` no longer counts datagrams with the wrong magic.
That traffic shows up only in kernel counters.

## Not done

- `recvmmsg` batching for valid requests, the natural follow-up.
- `SO_LOCK_FILTER`. It is unnecessary, since no untrusted code runs in
  the process.
