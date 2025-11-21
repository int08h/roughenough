//! Network I/O Benchmark using Server-Side Metrics
//!
//! This benchmark measures server-side network I/O performance by:
//! 1. Spawning a Roughtime server with metrics collection enabled
//! 2. Flooding it with client requests for a fixed duration
//! 3. Reading the server's own metrics output (JSON files)
//! 4. Reporting batch processing latency and throughput
//!
//! The key advantage of using server-side metrics is that we measure actual
//! server processing time without client-side noise. This makes the results
//! directly comparable between different I/O implementations (mio vs io_uring).
//!
//! ## Usage
//!
//! ```bash
//! # Build the server and benchmark
//! cargo build --release --bin roughenough_server && cargo build --release --bin io_benchmark
//!
//! # Run the benchmark (measures current mio implementation)
//! target/release/io_benchmark
//!
//! # Save baseline before implementing io_uring
//! target/release/io_benchmark | tee baseline-mio.txt
//!
//! # After implementing io_uring, compare results
//! target/release/io_benchmark | tee results-io_uring.txt
//! diff -u baseline-mio.txt results-io_uring.txt
//! ```
//!
//! ## Metrics Reported
//!
//! - **Batch Processing Latency**: Server-side time to process batches of requests
//!   - Reported per batch size (1, 2, 4, 8, 16, 32, 64)
//!   - Percentiles: P50, P95, P99, P999
//! - **Throughput**: Responses per second (from server metrics)
//! - **Network Operations**: Send/receive counts and error rates
//!
//! Note: Loopback (127.0.0.1) understates io_uring benefits. For realistic
//! measurements, test on a real network interface.

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::{fs, io, thread};

use roughenough_protocol::ToFrame;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::Nonce;
use roughenough_server::metrics::snapshot::MetricsSnapshot;

const SERVER_PORT: u16 = 2003;
const METRICS_INTERVAL_SECS: u64 = 2;
const BENCHMARK_DURATION_SECS: u64 = 10;
const WARMUP_DURATION_SECS: u64 = 3;

/// Generate a random nonce for a Roughtime request
fn random_nonce() -> Nonce {
    let mut bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).expect("RNG should be available");
    Nonce::from(bytes)
}

/// Create a wire-encoded Roughtime request
fn create_request() -> Vec<u8> {
    let nonce = random_nonce();
    let request = Request::new(&nonce);
    request
        .as_frame_bytes()
        .expect("Request encoding should succeed")
}

/// Find the server binary in the workspace
fn find_server_binary() -> PathBuf {
    // Try to find the workspace root by looking for the server binary
    // relative to the current executable
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");

    // When running the compiled binary, it's typically in target/release/
    // so we can find the server binary in the same directory
    if let Some(parent) = current_exe.parent() {
        let server_path = parent.join("roughenough_server");
        if server_path.exists() {
            return server_path;
        }
    }

    // Fallback: try using CARGO_MANIFEST_DIR if available (when running via cargo)
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let workspace_root = Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .expect("Failed to find workspace root");

        let server_path = workspace_root.join("target/release/roughenough_server");
        if server_path.exists() {
            return server_path;
        }
    }

    eprintln!("Server binary 'roughenough_server' not found");
    eprintln!("Build it with: cargo build --release --bin roughenough_server");
    eprintln!("Make sure the server binary is in the same directory as this benchmark");
    std::process::exit(1);
}

/// Spawn the Roughtime server with metrics output enabled
fn spawn_server(metrics_dir: &Path) -> Child {
    let server_path = find_server_binary();

    let mut server = Command::new(&server_path)
        .arg("--metrics-interval")
        .arg(METRICS_INTERVAL_SECS.to_string())
        .arg("--metrics-output")
        .arg(metrics_dir)
        .arg("--port")
        .arg(SERVER_PORT.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("Failed to spawn server at {:?}: {}", server_path, e);
            std::process::exit(1);
        });

    // Give server time to start
    thread::sleep(Duration::from_millis(100));

    // Verify server started successfully
    if let Ok(Some(status)) = server.try_wait() {
        eprintln!("Server exited unexpectedly with status: {}", status);
        std::process::exit(1);
    }

    server
}

/// Wait for server to be ready by probing with requests
fn wait_for_server_ready(timeout: Duration) {
    let start = Instant::now();
    let probe_socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind probe socket");
    probe_socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("Failed to set probe timeout");

    let server_addr: SocketAddr = format!("127.0.0.1:{}", SERVER_PORT).parse().unwrap();
    let mut response_buf = vec![0u8; 2048];

    while start.elapsed() < timeout {
        let request = create_request();
        if probe_socket.send_to(&request, server_addr).is_ok()
            && probe_socket.recv_from(&mut response_buf).is_ok()
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }

    eprintln!("Server did not become ready within {:?}", timeout);
    std::process::exit(1);
}

/// Kill the server process and wait for it to exit
fn kill_server(mut server: Child) {
    let _ = server.kill();
    let _ = server.wait();
}

/// Send requests to the server for a specified duration using separate threads.
///
/// This function uses two threads:
/// - Sender thread: blasts requests as fast as possible
/// - Receiver thread: drains responses independently
///
/// This approach maximizes send throughput without being limited by receive latency.
fn flood_server(duration: Duration) -> usize {
    let server_addr: SocketAddr = format!("127.0.0.1:{}", SERVER_PORT).parse().unwrap();

    // Shared state
    let stop_flag = Arc::new(AtomicBool::new(false));
    let requests_sent = Arc::new(AtomicUsize::new(0));
    let responses_received = Arc::new(AtomicUsize::new(0));

    // Create a single socket and clone it for the receiver thread.
    // Both handles share the same underlying socket.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind client socket");
    socket
        .connect(server_addr)
        .expect("Failed to connect to server");
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .expect("Failed to set read timeout");

    let recv_socket = socket.try_clone().expect("Failed to clone socket");

    // Spawn receiver thread
    let recv_stop = Arc::clone(&stop_flag);
    let recv_count = Arc::clone(&responses_received);
    let receiver_handle = thread::spawn(move || {
        let mut response_buf = vec![0u8; 2048];
        while !recv_stop.load(Ordering::Relaxed) {
            if recv_socket.recv(&mut response_buf).is_ok() {
                recv_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Drain any remaining responses after stop signal
        recv_socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .ok();
        let drain_start = Instant::now();
        while drain_start.elapsed() < Duration::from_millis(500) {
            if recv_socket.recv(&mut response_buf).is_ok() {
                recv_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    // Sender runs in main thread
    let start = Instant::now();
    while start.elapsed() < duration {
        let request = create_request();
        if socket.send(&request).is_ok() {
            requests_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Signal receiver to stop and wait for drain
    stop_flag.store(true, Ordering::Relaxed);
    receiver_handle.join().expect("Receiver thread panicked");

    let sent = requests_sent.load(Ordering::Relaxed);
    let received = responses_received.load(Ordering::Relaxed);

    println!("Client sent {} requests", sent);
    println!("Client received {} responses", received);

    received
}

/// Find the most recent metrics file in the directory
fn find_latest_metrics_file(metrics_dir: &Path) -> io::Result<PathBuf> {
    let mut latest_file: Option<PathBuf> = None;
    let mut latest_time = std::time::SystemTime::UNIX_EPOCH;

    for entry in fs::read_dir(metrics_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("roughenough-metrics-") && s.ends_with(".json"))
                .unwrap_or(false)
        {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if modified > latest_time {
                        latest_time = modified;
                        latest_file = Some(path);
                    }
                }
            }
        }
    }

    latest_file.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "No metrics files found in directory",
        )
    })
}

/// Load and parse the most recent metrics snapshot
fn load_metrics_snapshot(metrics_dir: &Path) -> io::Result<MetricsSnapshot> {
    let metrics_file = find_latest_metrics_file(metrics_dir)?;
    let json_data = fs::read_to_string(&metrics_file)?;
    let snapshot: MetricsSnapshot = serde_json::from_str(&json_data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse metrics JSON: {}", e),
        )
    })?;
    Ok(snapshot)
}

/// Display batch timing metrics in a comparable format
fn display_batch_metrics(snapshot: &MetricsSnapshot) {
    println!("\n=== Batch Processing Latency (Server-Side) ===");
    println!();

    let reports = snapshot.totals.responses.batch_timing.report();

    // Filter to only batches with data
    let active_reports: Vec<_> = reports.iter().filter(|r| r.count > 0).collect();

    if active_reports.is_empty() {
        println!("No data collected");
        return;
    }

    println!(
        "Batch Size |     Count |        P50 |        P95 |        P99 |       P999 |   P50/resp"
    );
    println!(
        "-----------|-----------|------------|------------|------------|------------|------------"
    );

    for report in active_reports {
        let per_response = report.median / report.batch_size as u32;
        println!(
            "{:>10} | {:>9} | {:>10.1?} | {:>10.1?} | {:>10.1?} | {:>10.1?} | {:>10.3?}",
            report.batch_size,
            report.count,
            report.median,
            report.p95,
            report.p99,
            report.p999,
            per_response
        );
    }
}

/// Display throughput and network metrics
fn display_throughput_metrics(snapshot: &MetricsSnapshot) {
    println!("\n=== Throughput (Server-Side) ===");
    println!(
        "Responses/sec:  {:.0}",
        snapshot.totals.responses_per_second
    );
    println!(
        "Throughput:     {:.2} MB/s",
        snapshot.totals.mbytes_per_second
    );
    println!(
        "Total responses: {}",
        snapshot.totals.responses.num_responses
    );

    println!("\n=== Network Operations ===");
    println!(
        "Successful sends: {}",
        snapshot.totals.network.num_successful_sends
    );
    println!(
        "Failed sends:     {}",
        snapshot.totals.network.num_failed_sends
    );
    println!(
        "Failed recvs:     {}",
        snapshot.totals.network.num_failed_recvs
    );
    println!(
        "WOULDBLOCK recvs: {}",
        snapshot.totals.network.num_recv_wouldblock
    );

    let send_success_rate = if snapshot.totals.network.num_successful_sends > 0 {
        100.0 * snapshot.totals.network.num_successful_sends as f64
            / (snapshot.totals.network.num_successful_sends
                + snapshot.totals.network.num_failed_sends) as f64
    } else {
        0.0
    };
    println!("Send success rate: {:.2}%", send_success_rate);
}

fn main() {
    println!("io_benchmark");
    println!("============\n");

    // Create temporary directory for metrics
    let temp_dir =
        std::env::temp_dir().join(format!("roughenough-benchmark-{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("Failed to create metrics directory");
    println!("Metrics directory: {}", temp_dir.display());

    // Spawn server
    println!("Starting server...");
    let server = spawn_server(&temp_dir);

    // Wait for server to be ready
    println!("Waiting for server to be ready...");
    wait_for_server_ready(Duration::from_secs(5));
    println!("Server is ready");

    // Warmup period
    println!("\nWarming up for {}s...", WARMUP_DURATION_SECS);
    flood_server(Duration::from_secs(WARMUP_DURATION_SECS));

    // Wait for one metrics interval to get a clean snapshot
    println!("Waiting for metrics reset...");
    thread::sleep(Duration::from_secs(METRICS_INTERVAL_SECS + 1));

    // Main benchmark period
    println!("\nBenchmarking for {}s...", BENCHMARK_DURATION_SECS);
    let start = Instant::now();
    flood_server(Duration::from_secs(BENCHMARK_DURATION_SECS));
    let elapsed = start.elapsed();
    println!("Benchmark completed in {:.2}s", elapsed.as_secs_f64());

    // Wait for final metrics to be written
    println!("Waiting for final metrics...");
    thread::sleep(Duration::from_secs(METRICS_INTERVAL_SECS + 1));

    // Kill server
    kill_server(server);

    // Load and display metrics
    println!("\nLoading metrics...");
    match load_metrics_snapshot(&temp_dir) {
        Ok(snapshot) => {
            display_batch_metrics(&snapshot);
            display_throughput_metrics(&snapshot);

            println!("\n=== Syscall Measurement (External) ===");
            println!("To measure syscall counts, run this benchmark under perf:");
            println!();
            println!("  sudo perf stat -e 'syscalls:sys_enter_*' \\");
            println!("      target/release/io_benchmark");
            println!();
        }
        Err(e) => {
            eprintln!("Failed to load metrics: {}", e);
            std::process::exit(1);
        }
    }

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);

    println!("\n✓ Benchmark completed successfully");
}
