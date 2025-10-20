//! metrics output

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::metrics::aggregator::WorkerMetrics;
use crate::metrics::types::{NetworkMetrics, RequestMetrics, ResponseMetrics};

/// Complete JSON metrics output structure
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Timestamp when the metrics were generated
    pub timestamp: i64,
    /// Duration in seconds this metrics report covers
    pub duration_secs: f64,
    /// Per-worker metrics
    pub workers: Vec<WorkerMetrics>,
    /// Aggregated totals across all workers
    pub totals: AggregatedMetrics,
}

/// Aggregated metrics across all workers
#[derive(Debug, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub network: NetworkMetrics,
    pub requests: RequestMetrics,
    pub responses: ResponseMetrics,
    pub total_requests: usize,
    pub responses_per_second: f64,
    pub mbytes_per_second: f64,
}

impl MetricsSnapshot {
    /// Create a MetricsSnapshot with pre-calculated aggregated metrics
    pub fn new(
        now: SystemTime,
        duration_secs: f64,
        workers: Vec<WorkerMetrics>,
        totals: AggregatedMetrics,
    ) -> Self {
        let timestamp = time_format::from_system_time(now).unwrap();
        Self {
            timestamp,
            duration_secs,
            workers,
            totals,
        }
    }

    /// Write metrics to a JSON file atomically
    pub fn write_to_file(&self, metrics_path: &Path) -> Result<String, std::io::Error> {
        // Create filename with timestamp pattern
        let filename =
            time_format::strftime_utc("roughenough-metrics-%Y%m%d-%H%M%S.json", self.timestamp)
                .unwrap();

        let file_path = metrics_path.join(&filename);
        let temp_path = metrics_path.join(format!(".{}.tmp", &filename));

        // Write to temporary file first
        let mut temp_file = File::create(&temp_path)?;
        let json_data = serde_json::to_string(self)?;
        temp_file.write_all(json_data.as_bytes())?;
        temp_file.sync_all()?;

        // Atomically rename temp file to final name
        fs::rename(&temp_path, &file_path)?;

        debug!("Wrote {} bytes of metrics to {}", json_data.len(), file_path.display());
        Ok(filename)
    }
}

/// Calculate aggregated metrics from a slice of worker metrics
pub fn calc_aggregated_metrics(duration_secs: f64, workers: &[WorkerMetrics]) -> AggregatedMetrics {
    let mut total_network = NetworkMetrics::default();
    let mut total_requests = RequestMetrics::default();
    let mut total_responses = ResponseMetrics::default();

    // Calculate totals
    for worker in workers {
        total_network += worker.network;
        total_requests += worker.request;
        total_responses += worker.response.clone();
    }

    let total_request_count = total_requests.num_ok_requests
        + total_requests.num_bad_requests
        + total_requests.num_runt_requests
        + total_requests.num_jumbo_requests;

    let responses_per_second =
        total_responses.num_responses as f64 / duration_secs.max(f64::EPSILON);

    let mbytes_per_second = (total_responses.num_bytes_sent as f64 / (1024.0 * 1024.0))
        / duration_secs.max(f64::EPSILON);

    AggregatedMetrics {
        responses_per_second,
        mbytes_per_second,
        network: total_network,
        requests: total_requests,
        responses: total_responses,
        total_requests: total_request_count,
    }
}

/// Check if a directory exists and is writable
pub fn validate_metrics_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!(
            "Metrics output path does not exist: {}",
            path.display()
        ));
    }
    if !path.is_dir() {
        return Err(format!(
            "Metrics output path is not a directory: {}",
            path.display()
        ));
    }

    // Try to create a test file to check write permissions
    let test_file = path.join(".write_test");
    match File::create(&test_file) {
        Ok(_) => {
            // Clean up test file
            let _ = fs::remove_file(test_file);
            Ok(())
        }
        Err(e) => Err(format!(
            "Metrics directory is not writable: {} ({})",
            path.display(),
            e
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::SystemTime;

    use super::*;
    use crate::metrics::aggregator::WorkerMetrics;

    // Helper function to create test worker metrics
    fn create_test_worker_metrics(worker_id: usize, multiplier: u32) -> WorkerMetrics {
        WorkerMetrics {
            worker_id,
            network: NetworkMetrics {
                num_successful_sends: 50 * multiplier as usize,
                ..Default::default()
            },
            request: RequestMetrics {
                num_ok_requests: 48 * multiplier as usize,
                num_bad_requests: multiplier as usize,
                ..Default::default()
            },
            response: ResponseMetrics {
                num_responses: 48 * multiplier as usize,
                num_bytes_sent: 512 * 1024 * multiplier as usize,
                batch_sizes: vec![0; 64],
            },
        }
    }

    #[test]
    fn snapshot_json_serialization() {
        let now = SystemTime::now();
        let duration_secs = 60.0;

        // Create simpler test data
        let workers = vec![
            create_test_worker_metrics(0, 2),
            create_test_worker_metrics(1, 1),
        ];

        // Calculate aggregated metrics
        let aggregated = calc_aggregated_metrics(duration_secs, &workers);

        // Create snapshot
        let snapshot = MetricsSnapshot::new(now, duration_secs, workers.clone(), aggregated);

        // Serialize to JSON
        let json_str = serde_json::to_string(&snapshot).expect("Failed to serialize");

        // Deserialize back
        let deserialized: MetricsSnapshot =
            serde_json::from_str(&json_str).expect("Failed to deserialize");

        // Verify basic fields
        assert_eq!(deserialized.timestamp, snapshot.timestamp);
        assert_eq!(deserialized.duration_secs, duration_secs);
        assert_eq!(deserialized.workers.len(), 2);

        // Verify worker data roundtrips correctly
        assert_eq!(deserialized.workers[0].worker_id, 0);
        assert_eq!(deserialized.workers[0].network.num_successful_sends, 100);
        assert_eq!(deserialized.workers[0].request.num_ok_requests, 96);

        assert_eq!(deserialized.workers[1].worker_id, 1);
        assert_eq!(deserialized.workers[1].network.num_successful_sends, 50);
        assert_eq!(deserialized.workers[1].request.num_ok_requests, 48);

        // Verify aggregated totals
        assert_eq!(deserialized.totals.network.num_successful_sends, 150);
        assert_eq!(deserialized.totals.requests.num_ok_requests, 144);
        assert_eq!(deserialized.totals.responses.num_responses, 144);

        // Verify calculated rates
        let expected_responses_per_sec = 144.0 / 60.0;
        let expected_mbytes_per_sec = (1024.0 * 1024.0 + 512.0 * 1024.0) / (1024.0 * 1024.0) / 60.0;

        assert!(
            (deserialized.totals.responses_per_second - expected_responses_per_sec).abs() < 0.01
        );
        assert!((deserialized.totals.mbytes_per_second - expected_mbytes_per_sec).abs() < 0.01);
    }

    #[test]
    fn empty_workers_array() {
        // Test edge case: empty workers array
        let now = SystemTime::now();

        let empty_aggregated = calc_aggregated_metrics(60.0, &[]);
        let empty_snapshot = MetricsSnapshot::new(now, 60.0, vec![], empty_aggregated);

        let empty_json = serde_json::to_string(&empty_snapshot).expect("Failed to serialize empty");
        let empty_deserialized: MetricsSnapshot =
            serde_json::from_str(&empty_json).expect("Failed to deserialize empty");

        assert_eq!(empty_deserialized.workers.len(), 0);
        assert_eq!(empty_deserialized.totals.total_requests, 0);
        assert_eq!(empty_deserialized.totals.responses_per_second, 0.0);
        assert_eq!(empty_deserialized.totals.mbytes_per_second, 0.0);
    }

    #[test]
    fn output_directory_checks() {
        use std::env;
        let temp_dir = env::temp_dir();

        // Test 1: Non-existent directory
        let result = validate_metrics_directory(Path::new("/nonexistent/path"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));

        // Test 2: File instead of directory
        let temp_file = temp_dir.join("not_a_directory.txt");
        fs::write(&temp_file, "test").unwrap();

        let result = validate_metrics_directory(&temp_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a directory"));
        fs::remove_file(&temp_file).unwrap();

        // Test 3: Valid directory
        assert!(validate_metrics_directory(&temp_dir).is_ok());

        // Test 4: Write permission check
        let test_dir = temp_dir.join("metrics_test_dir");
        fs::create_dir_all(&test_dir).unwrap();

        assert!(validate_metrics_directory(&test_dir).is_ok());
        assert!(
            !test_dir.join(".write_test").exists(),
            "Test file should be cleaned up"
        );

        fs::remove_dir(&test_dir).unwrap();
    }
}
