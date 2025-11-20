//! Standalone server metrics benchmark
//!
//! This benchmark measures server-side I/O performance.
//!
//! ## Purpose
//!
//! Measures server performance by spawning a real server process and measuring:
//! - Round-trip latency distribution with comprehensive percentiles (P50, P90, P95, P99, P999)
//! - Maximum server throughput (responses/second)
//!
//! ## Critical: Measuring Syscalls for mio vs io_uring Comparison
//!
//! **The primary benefit of io_uring is syscall reduction (50-90% expected).**
//! This benchmark measures latency and throughput, but you MUST also measure syscalls
//! using Linux `perf` to verify io_uring's core benefit.
//!
//! ### Measuring Syscalls with perf
//!
//! ```bash
//! # Measure all syscalls during benchmark (mio baseline)
//! sudo perf stat -e 'syscalls:sys_enter_*' \
//!     cargo bench -p roughenough-server --bench server_metrics
//!
//! # Focus on network syscalls (mio)
//! sudo perf stat -e 'syscalls:sys_enter_recvfrom' \
//!     -e 'syscalls:sys_enter_sendto' \
//!     -e 'syscalls:sys_enter_epoll_wait' \
//!     cargo bench -p roughenough-server --bench server_metrics
//!
//! # After implementing io_uring, measure io_uring syscalls
//! sudo perf stat -e 'syscalls:sys_enter_recvfrom' \
//!     -e 'syscalls:sys_enter_sendto' \
//!     -e 'syscalls:sys_enter_io_uring_enter' \
//!     cargo bench -p roughenough-server --bench server_metrics
//!
//! # Expected io_uring result: 50-90% reduction in total syscalls
//! ```
//!
//! ### Expected io_uring Improvements
//!
//! | Metric | Expected Change | Why |
//! |--------|----------------|-----|
//! | Syscalls | -50% to -90% | io_uring batches operations |
//! | Throughput (loopback) | +10% to +30% | Reduced syscall overhead |
//! | Throughput (real NIC) | +50% to +200% | Zero-copy, interrupt reduction |
//! | Latency (loopback) | +5% to +15% | Minimal on loopback |
//! | Latency (real NIC) | +20% to +50% | Significant under load |
//! | CPU cycles/request | -20% to -40% | Fewer kernel transitions |
//!
//! ## Loopback Limitations
//!
//! ⚠️  **WARNING**: This benchmark uses loopback (127.0.0.1) which significantly
//! understates io_uring benefits. Loopback bypasses:
//! - Actual NIC interaction (no DMA, no interrupts)
//! - Zero-copy optimizations
//! - Buffer registration benefits
//!
//! Loopback results should be used for:
//! - Fast iteration during development
//! - Regression testing
//! - Relative performance comparison
//!
//! For realistic io_uring performance, test on a real network interface.
//!
//! ## Usage
//!
//! ```bash
//! # Build the server first
//! cargo build --release --bin roughenough_server
//!
//! # Run the standalone metrics benchmark
//! cargo bench -p roughenough-server --bench server_metrics
//!
//! # Save baseline before io_uring implementation
//! cargo bench -p roughenough-server --bench server_metrics > baseline_mio.txt
//!
//! # After io_uring implementation
//! cargo bench -p roughenough-server --bench server_metrics > results_io_uring.txt
//!
//! # Compare results
//! diff -u baseline_mio.txt results_io_uring.txt
//! ```
//!
//! This benchmark complements `server_network` which uses Divan for batch processing tests.

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use roughenough_protocol::ToFrame;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::Nonce;
use roughenough_server::metrics::latency::LatencyStats;

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

/// Benchmark: Server latency distribution (round-trip)
///
/// Measures round-trip latency distribution to identify both typical and tail latency.
/// Round-trip time = client send → server receive → server process → server send → client receive.
///
/// Note: Includes constant client-side syscall overhead (sendto + recvfrom) which is identical
/// for both mio and io_uring implementations, making the comparison valid. The server processing
/// time dominates in the measurement.
///
/// Collects 50,000 samples for detailed distribution analysis including high percentiles (P9999).
fn benchmark_latency_distribution() {
    println!("\n=== Server Latency Distribution (Round-Trip) ===");

    let (server, port) = spawn_server();
    wait_for_server_ready(port, Duration::from_secs(2));

    let socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind client socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("Failed to set read timeout");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let iterations = 50_000;
    let start = Instant::now();
    let mut stats = LatencyStats::new(iterations as usize);
    let mut response_buf = vec![0u8; 2048];

    for _ in 0..iterations {
        let request = create_request();

        // Measure full round-trip time
        let rtt_start = Instant::now();
        socket
            .send_to(&request, server_addr)
            .expect("Failed to send request");

        match socket.recv_from(&mut response_buf) {
            Ok((size, _)) => {
                let round_trip_time = rtt_start.elapsed();
                stats.record(round_trip_time);
                std::hint::black_box(size);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => panic!("Receive error: {}", e),
        }
    }

    let total_elapsed = start.elapsed();

    println!("Samples collected: {}", iterations);
    println!("Total time: {:?}", total_elapsed);
    println!("Average RTT: {:?}", stats.mean());
    println!("P50 (median): {:?}", stats.median());
    println!("P90: {:?}", stats.percentile(0.90));
    println!("P95: {:?}", stats.p95());
    println!("P99: {:?}", stats.p99());
    println!("P999: {:?}", stats.p999());
    println!("P9999: {:?}", stats.percentile(0.9999));

    kill_server(server);
}

/// Benchmark: Server throughput
///
/// Measures server processing throughput (responses/second) by flooding it with requests
/// from a background thread and measuring only the rate of responses received.
/// Client send rate is not measured, only server output rate.
/// Runs for 5 seconds to get stable throughput measurements.
fn benchmark_server_throughput() {
    println!("\n=== Server Throughput ===");

    let (server, port) = spawn_server();
    wait_for_server_ready(port, Duration::from_secs(2));

    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind socket");
    let send_socket = recv_socket.try_clone().expect("Failed to clone socket");

    recv_socket
        .set_nonblocking(true)
        .expect("Failed to set nonblocking");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Background thread continuously sends requests (not measured)
    let (stop_tx, stop_rx) = mpsc::channel();
    let sender_handle = thread::spawn(move || {
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            let request = create_request();
            let _ = send_socket.send_to(&request, server_addr);
            thread::yield_now();
        }
    });

    // Give sender time to build up a queue
    thread::sleep(Duration::from_millis(100));

    // Measure only response reception rate (server-limited throughput)
    let mut response_buf = vec![0u8; 2048];
    let mut received = 0;
    let start = Instant::now();
    let duration = Duration::from_secs(5);

    while start.elapsed() < duration {
        if let Ok((size, _)) = recv_socket.recv_from(&mut response_buf) {
            std::hint::black_box(size);
            received += 1;
        } else {
            thread::yield_now();
        }
    }

    let _ = stop_tx.send(());
    let _ = sender_handle.join();

    let elapsed = start.elapsed();
    let throughput = (received as f64) / elapsed.as_secs_f64();

    println!("Responses received: {}", received);
    println!("Duration: {:?}", elapsed);
    println!("Throughput: {:.0} responses/sec", throughput);
    println!("Average latency: {:.2?}", elapsed / received);

    kill_server(server);
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║         Server I/O Performance Metrics Benchmark               ║");
    println!("║   (Standalone - Client overhead excluded from all measures)    ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    benchmark_latency_distribution();
    benchmark_server_throughput();

    println!("\n✓ All benchmarks completed");
}
