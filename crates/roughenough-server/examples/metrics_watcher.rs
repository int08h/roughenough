//! Example client that watches a metrics directory and displays new metrics files

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, thread};

use roughenough_server::metrics::snapshot::MetricsSnapshot;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <metrics-directory>", args[0]);
        std::process::exit(1);
    }

    let metrics_dir = Path::new(&args[1]);
    if !metrics_dir.exists() || !metrics_dir.is_dir() {
        eprintln!("Error: {} is not a valid directory", metrics_dir.display());
        std::process::exit(1);
    }

    println!("Watching metrics directory: {}", metrics_dir.display());
    println!("Press Ctrl+C to stop\n");

    let mut seen_files = HashSet::new();

    loop {
        process_new_metrics_files(metrics_dir, &mut seen_files);
        thread::sleep(Duration::from_millis(500));
    }
}

fn process_new_metrics_files(metrics_dir: &Path, seen_files: &mut HashSet<String>) {
    let json_files = match get_json_files(metrics_dir) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("Error reading directory: {e}");
            return;
        }
    };

    for path in json_files {
        let filename = path.file_name().unwrap().to_string_lossy().to_string();

        if seen_files.contains(&filename) {
            continue;
        }

        seen_files.insert(filename.clone());
        process_metrics_file(&path, &filename);
    }
}

fn get_json_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let entries = fs::read_dir(dir)?;

    Ok(entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect())
}

fn process_metrics_file(path: &Path, filename: &str) {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) => {
            eprintln!("Error reading {}: {}", filename, e);
            return;
        }
    };

    let metrics = match serde_json::from_str::<MetricsSnapshot>(&contents) {
        Ok(metrics) => metrics,
        Err(e) => {
            eprintln!("Error parsing {}: {}", filename, e);
            return;
        }
    };

    display_metrics(filename, &metrics);
}

fn display_metrics(filename: &str, metrics: &MetricsSnapshot) {
    println!("=== New Metrics File: {} ===", filename);
    println!("Timestamp: {}", metrics.timestamp);
    println!("Duration: {:.1}s", metrics.duration_secs);
    println!();

    println!("Aggregate Totals:");
    println!("  Total Requests: {}", metrics.totals.total_requests);
    println!("  - OK: {}", metrics.totals.requests.num_ok_requests);
    println!("  - Bad: {}", metrics.totals.requests.num_bad_requests);
    println!("  - Runt: {}", metrics.totals.requests.num_runt_requests);
    println!("  - Jumbo: {}", metrics.totals.requests.num_jumbo_requests);
    println!();

    println!("  Responses: {}", metrics.totals.responses.num_responses);
    println!("  - Rate: {:.2} req/s", metrics.totals.responses_per_second);
    println!(
        "  - Bandwidth: {:.2} MB/s",
        metrics.totals.mbytes_per_second
    );
    println!();

    println!("  Network:");
    println!(
        "  - Successful sends: {}",
        metrics.totals.network.num_successful_sends
    );
    println!(
        "  - Failed sends: {}",
        metrics.totals.network.num_failed_sends
    );
    println!(
        "  - Failed polls: {}",
        metrics.totals.network.num_failed_polls
    );
    println!(
        "  - Failed recvs: {}",
        metrics.totals.network.num_failed_recvs
    );
    println!(
        "  - Recv would block: {}",
        metrics.totals.network.num_recv_wouldblock
    );
    println!();

    // Show per-worker summary if there are multiple workers
    if metrics.workers.len() > 1 {
        println!("  Per-Worker Summary:");
        for worker in &metrics.workers {
            let worker_total = worker.request.num_ok_requests
                + worker.request.num_bad_requests
                + worker.request.num_runt_requests
                + worker.request.num_jumbo_requests;

            if worker_total > 0 || worker.response.num_responses > 0 {
                println!(
                    "    Worker {}: {} requests, {} responses",
                    worker.worker_id, worker_total, worker.response.num_responses
                );
            }
        }
    }

    println!("\n");
}
