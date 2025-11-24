//! Network I/O Benchmark - Multi-Backend Comparison
//!
//! This benchmark measures server-side network I/O performance by:
//! 1. Spawning a Roughtime server with each backend (mio, recvmmsg)
//! 2. Flooding it with client requests for a fixed duration
//! 3. Reading the server's own metrics output (JSON files)
//! 4. Reporting batch processing latency, throughput, and syscall efficiency
//!
//! The key advantage of using server-side metrics is that we measure actual
//! server processing time without client-side noise. This makes the results
//! directly comparable between different I/O implementations.
//!
//! ## Usage
//!
//! ```bash
//! # Build the server and benchmark
//! cargo build --release --bin roughenough_server
//! cargo build --release --bin io_benchmark
//!
//! # Run the benchmark (tests all available backends)
//! target/release/io_benchmark
//! ```
//!
//! ## Metrics Reported
//!
//! - **Batch Processing Latency**: Server-side time to process batches of requests
//!   - Reported per batch size (1, 2, 4, 8, 16, 32, 64)
//!   - Percentiles: P50, P95, P99, P999
//! - **Throughput**: Responses per second (from server metrics)
//! - **Syscall Efficiency**: Messages per recv syscall (recvmmsg advantage)
//! - **Network Operations**: Send/receive counts and error rates
//!
//! Note: Loopback (127.0.0.1) understates recvmmsg benefits. For realistic
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
use roughenough_server::metrics::batch::TimingReport;
use roughenough_server::metrics::snapshot::MetricsSnapshot;

const SERVER_PORT: u16 = 2003;
const METRICS_INTERVAL_SECS: u64 = 2;
const BENCHMARK_DURATION_SECS: u64 = 10;
const WARMUP_DURATION_SECS: u64 = 3;

/// Available backends to test
#[cfg(target_os = "linux")]
const BACKENDS: &[&str] = &["mio", "recvmmsg"];

#[cfg(not(target_os = "linux"))]
const BACKENDS: &[&str] = &["mio"];

/// Results from benchmarking a single backend
struct BenchmarkResult {
    backend: String,
    responses_per_second: f64,
    mbytes_per_second: f64,
    recv_syscalls: usize,
    messages_per_recv_syscall: f64,
    /// The batch size with the most samples (effective batch size)
    dominant_batch_size: u8,
    /// P50 latency for the dominant batch size
    dominant_p50: Duration,
    total_responses: usize,
    batch_timing: Vec<TimingReport>,
}

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
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");

    if let Some(parent) = current_exe.parent() {
        let server_path = parent.join("roughenough_server");
        if server_path.exists() {
            return server_path;
        }
    }

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
    std::process::exit(1);
}

/// Spawn the Roughtime server with the specified backend
fn spawn_server(metrics_dir: &Path, backend: &str) -> Child {
    let server_path = find_server_binary();

    let mut server = Command::new(&server_path)
        .arg("--metrics-interval")
        .arg(METRICS_INTERVAL_SECS.to_string())
        .arg("--metrics-output")
        .arg(metrics_dir)
        .arg("--port")
        .arg(SERVER_PORT.to_string())
        .arg("--io-backend")
        .arg(backend)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("Failed to spawn server at {:?}: {}", server_path, e);
            std::process::exit(1);
        });

    thread::sleep(Duration::from_millis(100));

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

/// Kill the server process
fn kill_server(mut server: Child) {
    let _ = server.kill();
    let _ = server.wait();
}

/// Flood the server with requests for the specified duration
fn flood_server(duration: Duration) -> usize {
    let server_addr: SocketAddr = format!("127.0.0.1:{}", SERVER_PORT).parse().unwrap();

    let stop_flag = Arc::new(AtomicBool::new(false));
    let requests_sent = Arc::new(AtomicUsize::new(0));
    let responses_received = Arc::new(AtomicUsize::new(0));

    let socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind client socket");
    socket
        .connect(server_addr)
        .expect("Failed to connect to server");
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .expect("Failed to set read timeout");

    let recv_socket = socket.try_clone().expect("Failed to clone socket");

    let recv_stop = Arc::clone(&stop_flag);
    let recv_count = Arc::clone(&responses_received);
    let receiver_handle = thread::spawn(move || {
        let mut response_buf = vec![0u8; 2048];
        while !recv_stop.load(Ordering::Relaxed) {
            if recv_socket.recv(&mut response_buf).is_ok() {
                recv_count.fetch_add(1, Ordering::Relaxed);
            }
        }

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

    let start = Instant::now();
    while start.elapsed() < duration {
        let request = create_request();
        if socket.send(&request).is_ok() {
            requests_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    stop_flag.store(true, Ordering::Relaxed);
    receiver_handle.join().expect("Receiver thread panicked");

    responses_received.load(Ordering::Relaxed)
}

/// Find the most recent metrics file
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

/// Load and parse metrics snapshot
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

/// Extract the dominant batch size and its P50 latency from batch timing.
///
/// Returns (batch_size, p50) for the batch size with the most samples.
fn extract_dominant_batch(snapshot: &MetricsSnapshot) -> (u8, Duration) {
    let reports = snapshot.totals.responses.batch_timing.report();
    // Find the batch size with the most samples for representative metrics
    reports
        .iter()
        .filter(|r| r.count > 0)
        .max_by_key(|r| r.count)
        .map(|r| (r.batch_size, r.median))
        .unwrap_or((0, Duration::ZERO))
}

/// Run benchmark for a single backend
fn run_benchmark_for_backend(backend: &str) -> io::Result<BenchmarkResult> {
    let temp_dir = std::env::temp_dir().join(format!(
        "roughenough-bench-{}-{}",
        backend,
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir)?;

    println!("  Starting server with {} backend...", backend);
    let server = spawn_server(&temp_dir, backend);

    wait_for_server_ready(Duration::from_secs(5));

    println!("  Warming up for {}s...", WARMUP_DURATION_SECS);
    flood_server(Duration::from_secs(WARMUP_DURATION_SECS));

    // Wait for metrics reset
    thread::sleep(Duration::from_secs(METRICS_INTERVAL_SECS + 1));

    println!("  Benchmarking for {}s...", BENCHMARK_DURATION_SECS);
    let _client_responses = flood_server(Duration::from_secs(BENCHMARK_DURATION_SECS));

    // Wait for final metrics
    thread::sleep(Duration::from_secs(METRICS_INTERVAL_SECS + 1));

    kill_server(server);

    let snapshot = load_metrics_snapshot(&temp_dir)?;
    let _ = fs::remove_dir_all(&temp_dir);

    let recv_syscalls = snapshot.totals.network.num_recv_syscalls;
    let total_responses = snapshot.totals.responses.num_responses;
    let messages_per_recv = if recv_syscalls > 0 {
        total_responses as f64 / recv_syscalls as f64
    } else {
        0.0
    };

    let batch_timing: Vec<TimingReport> = snapshot
        .totals
        .responses
        .batch_timing
        .report()
        .into_iter()
        .filter(|r| r.count > 0)
        .collect();

    let (dominant_batch_size, dominant_p50) = extract_dominant_batch(&snapshot);

    Ok(BenchmarkResult {
        backend: backend.to_string(),
        responses_per_second: snapshot.totals.responses_per_second,
        mbytes_per_second: snapshot.totals.mbytes_per_second,
        recv_syscalls,
        messages_per_recv_syscall: messages_per_recv,
        dominant_batch_size,
        dominant_p50,
        total_responses,
        batch_timing,
    })
}

/// Display batch timing details for a single backend
fn display_batch_metrics(result: &BenchmarkResult) {
    if result.batch_timing.is_empty() {
        return;
    }

    println!("\n  Batch Processing Latency:");
    println!(
        "  {:>10} | {:>9} | {:>10} | {:>10} | {:>10} | {:>10}",
        "Batch Size", "Count", "P50", "P95", "P99", "P999"
    );
    println!("  {}", "-".repeat(70));

    for report in &result.batch_timing {
        println!(
            "  {:>10} | {:>9} | {:>10.1?} | {:>10.1?} | {:>10.1?} | {:>10.1?}",
            report.batch_size, report.count, report.median, report.p95, report.p99, report.p999
        );
    }
}

/// Display comparison table
fn display_comparison(results: &[BenchmarkResult]) {
    println!("\n=== Backend Comparison ===\n");

    println!(
        "{:<10} | {:>10} | {:>8} | {:>12} | {:>10} | {:>10} | {:>10} | {:>8}",
        "Backend", "Resp/sec", "MB/sec", "Msg/RecvCall", "RecvCalls", "BatchSize", "P50", "vs mio"
    );
    println!("{}", "-".repeat(97));

    let mio_result = results.iter().find(|r| r.backend == "mio");

    for result in results {
        let speedup = mio_result
            .map(|m| result.responses_per_second / m.responses_per_second)
            .unwrap_or(1.0);

        println!(
            "{:<10} | {:>10.0} | {:>8.2} | {:>12.1} | {:>10} | {:>10} | {:>10.1?} | {:>7.2}x",
            result.backend,
            result.responses_per_second,
            result.mbytes_per_second,
            result.messages_per_recv_syscall,
            result.recv_syscalls,
            result.dominant_batch_size,
            result.dominant_p50,
            speedup
        );
    }

    // Syscall efficiency summary
    if let (Some(mio), Some(recvmmsg)) = (
        results.iter().find(|r| r.backend == "mio"),
        results.iter().find(|r| r.backend == "recvmmsg"),
    ) {
        println!("\n=== Syscall Efficiency ===");
        println!(
            "mio:      {} recv syscalls for {} messages ({:.1} msg/syscall)",
            mio.recv_syscalls, mio.total_responses, mio.messages_per_recv_syscall
        );
        println!(
            "recvmmsg: {} recv syscalls for {} messages ({:.1} msg/syscall)",
            recvmmsg.recv_syscalls, recvmmsg.total_responses, recvmmsg.messages_per_recv_syscall
        );

        if mio.recv_syscalls > 0 {
            let syscall_reduction =
                100.0 * (1.0 - recvmmsg.recv_syscalls as f64 / mio.recv_syscalls as f64);
            println!("Recv syscall reduction: {:.1}%", syscall_reduction);
        }
    }
}

fn main() {
    println!("io_benchmark - Multi-Backend Comparison");
    println!("========================================\n");

    let mut results = Vec::new();

    for backend in BACKENDS {
        println!("\n--- Testing {} backend ---", backend);

        match run_benchmark_for_backend(backend) {
            Ok(result) => {
                println!("  Responses/sec: {:.0}", result.responses_per_second);
                println!(
                    "  Messages per recv syscall: {:.1}",
                    result.messages_per_recv_syscall
                );
                display_batch_metrics(&result);
                results.push(result);
            }
            Err(e) => {
                eprintln!("  Failed: {}", e);
            }
        }
    }

    if !results.is_empty() {
        display_comparison(&results);
    }

    println!("\n=== Syscall Measurement (External) ===");
    println!("To measure syscall counts with perf:");
    println!();
    println!("  sudo perf stat -e 'syscalls:sys_enter_recvmsg,syscalls:sys_enter_recvmmsg' \\");
    println!("      target/release/io_benchmark");
    println!();

    println!("Benchmark completed");
}
