//! Metrics collection that periodically gathers metrics from worker threads

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, SystemTime};

use roughenough_protocol::util::ClockSource;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::metrics::snapshot::{AggregatedMetrics, MetricsSnapshot, calc_aggregated_metrics};
use crate::metrics::types::{NetworkMetrics, RequestMetrics, ResponseMetrics};

/// Snapshot of worker metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerMetrics {
    pub worker_id: usize,
    pub network: NetworkMetrics,
    pub request: RequestMetrics,
    pub response: ResponseMetrics,
}

/// Metrics collector that runs in a dedicated thread
pub struct MetricsAggregator {
    /// Consumer end of MPSC channel for metrics snapshots from workers
    metrics_channel: Receiver<WorkerMetrics>,
    /// One accumulator per worker, indexed on worker id
    aggregated_metrics: Vec<WorkerMetrics>,
    /// Reporting interval in seconds
    reporting_interval: Duration,
    /// Reference to the global shutdown flag
    keep_running: &'static AtomicBool,
    /// Common clock
    clock: ClockSource,
    /// Optional path for JSON metrics output
    metrics_path: Option<PathBuf>,
    /// Cumulative response count at the previous report; rates divide the
    /// interval delta, not the ever-growing cumulative totals
    prev_num_responses: usize,
    /// Cumulative bytes sent at the previous report
    prev_num_bytes_sent: usize,
}

impl MetricsAggregator {
    pub fn new(
        metrics_channel: Receiver<WorkerMetrics>,
        num_workers: usize,
        reporting_interval: Duration,
        keep_running: &'static AtomicBool,
        clock: ClockSource,
        metrics_path: Option<PathBuf>,
    ) -> Self {
        let aggregated_metrics = (0..num_workers)
            .map(|worker_id| WorkerMetrics {
                worker_id,
                network: NetworkMetrics::default(),
                request: RequestMetrics::default(),
                response: ResponseMetrics::default(),
            })
            .collect();

        Self {
            metrics_channel,
            aggregated_metrics,
            reporting_interval,
            keep_running,
            clock,
            metrics_path,
            prev_num_responses: 0,
            prev_num_bytes_sent: 0,
        }
    }

    /// Run the metrics collection loop
    pub fn run(mut self) {
        info!(
            "Reporting metrics every {}s",
            self.reporting_interval.as_secs()
        );

        let mut next_report = self.clock.epoch_seconds() + self.reporting_interval.as_secs();
        let mut last_report_time = self.clock.epoch_seconds();

        while self.keep_running.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(500));

            // Accumulate all pending metrics updates
            while let Ok(metrics) = self.metrics_channel.try_recv() {
                self.accumulate(metrics);
            }

            let now = self.clock.epoch_seconds();

            if now >= next_report {
                let elapsed_secs = (now - last_report_time) as f64;
                self.report_metrics(elapsed_secs);

                last_report_time = now;
                next_report = now + self.reporting_interval.as_secs();
            }
        }

        info!("Metrics collection shutting down");
    }

    /// Fold one worker snapshot into the cumulative per-worker totals
    fn accumulate(&mut self, metrics: WorkerMetrics) {
        let worker_id = metrics.worker_id;

        self.aggregated_metrics[worker_id].network += metrics.network;
        self.aggregated_metrics[worker_id].request += metrics.request;
        self.aggregated_metrics[worker_id].response += metrics.response;
    }

    /// Aggregate the cumulative totals and compute this interval's rates from
    /// the delta against the previous report
    fn take_interval_report(&mut self, elapsed_secs: f64) -> AggregatedMetrics {
        let aggregated = calc_aggregated_metrics(
            elapsed_secs,
            &self.aggregated_metrics,
            self.prev_num_responses,
            self.prev_num_bytes_sent,
        );

        self.prev_num_responses = aggregated.responses.num_responses;
        self.prev_num_bytes_sent = aggregated.responses.num_bytes_sent;
        aggregated
    }

    /// Report aggregated metrics
    fn report_metrics(&mut self, elapsed_secs: f64) {
        let now = SystemTime::now();

        let aggregated = self.take_interval_report(elapsed_secs);

        debug!("[METRICS] Cumulative metrics after {:.1}s", elapsed_secs);
        info!(
            "Network: send_ok={} send_fail={} poll_fail={} recv_fail={} recv_wouldblock={} oversized_dropped={}",
            aggregated.network.num_successful_sends,
            aggregated.network.num_failed_sends,
            aggregated.network.num_failed_polls,
            aggregated.network.num_failed_recvs,
            aggregated.network.num_recv_wouldblock,
            aggregated.network.num_oversized_dropped,
        );
        info!(
            "Requests: total={} ok={} bad={} runt={} oversized={}",
            aggregated.total_requests,
            aggregated.requests.num_ok_requests,
            aggregated.requests.num_bad_requests,
            aggregated.requests.num_runt_requests,
            aggregated.requests.num_oversized_requests
        );
        info!(
            "Responses: total={} bytes={:.1}MB, batch sizes={}",
            aggregated.responses.num_responses,
            aggregated.responses.num_bytes_sent as f64 / (1024.0 * 1024.0),
            aggregated.responses.counts_as_string(),
        );

        if let Some(ref metrics_path) = self.metrics_path {
            let snapshot = MetricsSnapshot::new(
                now,
                elapsed_secs,
                self.aggregated_metrics.clone(),
                aggregated,
            );

            if let Err(e) = snapshot.write_to_file(metrics_path) {
                error!("Failed to write metrics: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::sync_channel;

    use super::*;

    static TEST_KEEP_RUNNING: AtomicBool = AtomicBool::new(true);

    fn worker_snapshot(num_responses: usize, num_bytes_sent: usize) -> WorkerMetrics {
        WorkerMetrics {
            worker_id: 0,
            network: NetworkMetrics::default(),
            request: RequestMetrics::default(),
            response: ResponseMetrics {
                num_responses,
                num_bytes_sent,
                batch_sizes: [0; 64],
            },
        }
    }

    #[test]
    fn rates_use_interval_deltas_not_cumulative_totals() {
        let (_tx, rx) = sync_channel(1);
        let mut aggregator = MetricsAggregator::new(
            rx,
            1,
            Duration::from_secs(10),
            &TEST_KEEP_RUNNING,
            ClockSource::System,
            None,
        );

        // Interval 1: 100 responses / 1 MiB over 10s -> 10/s and 0.1 MiB/s
        aggregator.accumulate(worker_snapshot(100, 1024 * 1024));
        let report = aggregator.take_interval_report(10.0);
        assert!((report.responses_per_second - 10.0).abs() < 1e-9);
        assert!((report.mbytes_per_second - 0.1).abs() < 1e-9);
        assert_eq!(report.responses.num_responses, 100);

        // Interval 2: the same load again. The cumulative totals double, but
        // the rate must stay 10/s, not inflate to 20/s.
        aggregator.accumulate(worker_snapshot(100, 1024 * 1024));
        let report = aggregator.take_interval_report(10.0);
        assert!((report.responses_per_second - 10.0).abs() < 1e-9);
        assert!((report.mbytes_per_second - 0.1).abs() < 1e-9);
        assert_eq!(report.responses.num_responses, 200);
        assert_eq!(report.responses.num_bytes_sent, 2 * 1024 * 1024);
    }

    #[test]
    fn idle_interval_reports_zero_rate() {
        let (_tx, rx) = sync_channel(1);
        let mut aggregator = MetricsAggregator::new(
            rx,
            1,
            Duration::from_secs(10),
            &TEST_KEEP_RUNNING,
            ClockSource::System,
            None,
        );

        aggregator.accumulate(worker_snapshot(100, 4096));
        let _ = aggregator.take_interval_report(10.0);

        // No traffic this interval: cumulative counts persist, rates drop to 0
        let report = aggregator.take_interval_report(10.0);
        assert_eq!(report.responses_per_second, 0.0);
        assert_eq!(report.mbytes_per_second, 0.0);
        assert_eq!(report.responses.num_responses, 100);
    }
}
