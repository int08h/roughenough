//! Network I/O benchmark for measuring actual UDP socket performance
//!
//! This benchmark spawns a real server process and measures end-to-end network
//! performance including UDP send/receive operations, event loop overhead, and
//! batching efficiency.
//!
//! ## Purpose
//!
//! Designed to evaluate the performance impact of switching from mio-based async I/O
//! to io_uring. Unlike `server_ops.rs` which measures protocol logic in isolation,
//! this benchmark exercises the actual I/O paths.
//!
//! ## Metrics Measured
//!
//! - Batch processing efficiency at different sizes (8, 16, 32, 64 requests)
//!
//! For detailed latency distribution and throughput metrics, see the `server_metrics` benchmark.
//!
//! ## Usage
//!
//! ```bash
//! # Build the server first
//! cargo build --release --bin roughenough_server
//!
//! # Run the network benchmarks
//! cargo bench -p roughenough-server server_network
//!
//! # Measure syscall counts alongside benchmarks
//! perf stat -e 'syscalls:sys_enter_*' \
//!     cargo bench -p roughenough-server server_network
//! ```
//!
//! ## Methodology
//!
//! The benchmark:
//! 1. Spawns the actual `roughenough_server` process
//! 2. Pre-sends requests from separate threads (client overhead excluded from timing)
//! 3. Measures only server response reception time
//! 4. Computes latency percentiles and throughput
//! 5. Outputs detailed measurements (not just summary statistics)
//! 6. Cleans up the server process
//!
//! ## Limitations
//!
//! - Uses loopback (127.0.0.1) networking which has different characteristics
//!   than real network interfaces
//! - Loopback shortcuts some kernel operations that io_uring optimizes
//! - For definitive results, combine with `perf stat` to measure syscall counts
//!   and CPU efficiency
//!
//! ## Critical: Measuring Syscalls for mio vs io_uring Comparison
//!
//! **The primary benefit of io_uring is syscall reduction (50-90% expected).**
//! This benchmark measures batch processing efficiency, but you MUST also measure
//! syscalls using Linux `perf` to verify io_uring's core benefit.
//!
//! ```bash
//! # Measure syscalls with mio (baseline)
//! sudo perf stat -e 'syscalls:sys_enter_recvfrom' \
//!     -e 'syscalls:sys_enter_sendto' \
//!     -e 'syscalls:sys_enter_epoll_wait' \
//!     cargo bench -p roughenough-server --bench server_network
//!
//! # After implementing io_uring
//! sudo perf stat -e 'syscalls:sys_enter_io_uring_enter' \
//!     cargo bench -p roughenough-server --bench server_network
//!
//! # Expected: 50-90% reduction in total syscalls
//! ```
//!
//! ## Loopback Limitations
//!
//! ⚠️  **WARNING**: This benchmark uses loopback (127.0.0.1) which significantly
//! understates io_uring benefits. Loopback bypasses actual NIC interaction, DMA,
//! interrupts, and zero-copy optimizations. Results should be used for fast iteration
//! and relative comparison, not absolute performance claims.
//!
//! ## Interpreting Results
//!
//! When comparing mio vs io_uring:
//! - **Syscall count**: Expect 50-90% reduction with io_uring (measured via perf)
//! - **Batch throughput** (loopback): Expect 10-30% improvement under high load
//! - **Batch throughput** (real NIC): Expect 50-200% improvement
//! - **CPU efficiency**: Expect lower cycles/instructions per request (measured via perf)

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use divan::{Bencher, black_box};
use roughenough_protocol::ToFrame;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::Nonce;

fn main() {
    divan::main();
}

/// Helper to create a random nonce
fn random_nonce() -> Nonce {
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).expect("RNG should be available");
    Nonce::from(bytes)
}

/// Helper to create a wire-encoded Roughtime request
fn create_request() -> Vec<u8> {
    let nonce = random_nonce();
    let request = Request::new(&nonce);
    request
        .as_frame_bytes()
        .expect("Request encoding should succeed")
}

/// Spawn the Roughtime server and return the process handle
fn spawn_server() -> (Child, u16) {
    // Use release build for realistic performance
    // CARGO_MANIFEST_DIR points to the crate directory, navigate up to workspace root
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("Failed to find workspace root");

    let server_path = workspace_root.join("target/release/roughenough_server");

    if !server_path.exists() {
        panic!(
            "Server binary not found at {:?}. Run: cargo build --release --bin roughenough_server",
            server_path
        );
    }

    let mut server = Command::new(&server_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "Failed to spawn server at {:?}: {}. Check that the binary exists and is executable.",
                server_path, e
            )
        });

    // Check if server process started successfully
    thread::sleep(Duration::from_millis(50));
    if let Ok(Some(status)) = server.try_wait() {
        panic!("Server exited unexpectedly with status: {}", status);
    }

    // Server binds to port 2003 by default
    // Note: Caller must call wait_for_server_ready() before using
    (server, 2003)
}

/// Kill the server process
fn kill_server(mut server: Child) {
    let _ = server.kill();
    let _ = server.wait();
}

/// Wait for server to be ready by actively probing with requests
///
/// Sends probe requests until the server responds successfully or timeout is reached.
/// This ensures benchmarks measure steady-state performance, not startup overhead.
fn wait_for_server_ready(port: u16, timeout: Duration) {
    let start = Instant::now();
    let probe_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind probe socket");
    probe_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("Failed to set probe timeout");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let mut response_buf = vec![0u8; 2048];

    while start.elapsed() < timeout {
        let request = create_request();
        if probe_socket.send_to(&request, server_addr).is_ok()
            && probe_socket.recv_from(&mut response_buf).is_ok()
        {
            // Server is ready
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }

    panic!(
        "Server did not become ready within {:?}. Check server logs.",
        timeout
    );
}

/// Benchmark: Batch request processing
///
/// Pre-sends a batch of requests, then measures only the time to receive all responses.
/// This removes client send overhead and focuses on server processing throughput.
/// Exercises the server's batching behavior where multiple requests are
/// processed together using a Merkle tree.
///
/// Note: Each iteration spawns a fresh server to avoid state accumulation between runs.
#[divan::bench(
    max_time = 3,
    args = [8, 16, 32, 64],
)]
fn batch_requests(bencher: Bencher, batch_size: usize) {
    bencher.bench_local(|| {
        // Spawn fresh server for each iteration to avoid state accumulation
        let (server, port) = spawn_server();
        wait_for_server_ready(port, Duration::from_secs(2));

        let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind client socket");
        let send_socket = recv_socket.try_clone().expect("Failed to clone socket");

        recv_socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("Failed to set read timeout");

        let server_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        // Pre-send all requests (not timed - client overhead excluded)
        for _ in 0..batch_size {
            let request = create_request();
            send_socket
                .send_to(&request, server_addr)
                .expect("Failed to send request");
        }

        // Only time receiving responses (reflects server batch processing speed)
        let mut response_buf = vec![0u8; 2048];
        let mut received = 0;
        let start = Instant::now();

        while received < batch_size {
            match recv_socket.recv_from(&mut response_buf) {
                Ok((size, _)) => {
                    black_box(size);
                    received += 1;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => panic!("Receive error: {}", e),
            }
        }

        let elapsed = start.elapsed();

        kill_server(server);

        black_box((received, elapsed))
    });
}
