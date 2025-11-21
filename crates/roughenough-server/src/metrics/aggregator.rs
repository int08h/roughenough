//! Metrics collection that periodically gathers metrics from worker threads

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use crossbeam_channel::Receiver;
use roughenough_protocol::util::ClockSource;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::metrics::network::NetworkMetrics;
use crate::metrics::request::RequestMetrics;
use crate::metrics::response::ResponseMetrics;
use crate::metrics::snapshot::{MetricsSnapshot, calc_aggregated_metrics};

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
        }
    }

    /// Run the metrics collection loop
    pub fn run(mut self) {
        info!(
            "Reporting metrics every {}s",
            self.reporting_interval.as_secs()
        );

        let mut next_report_time = self.clock.epoch_seconds() + self.reporting_interval.as_secs();
        let mut last_report_time = self.clock.epoch_seconds();

        while self.keep_running.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(500));

            // Accumulate all pending metrics updates
            while let Ok(metrics) = self.metrics_channel.try_recv() {
                let worker_id = metrics.worker_id;

                self.aggregated_metrics[worker_id].network += metrics.network;
                self.aggregated_metrics[worker_id].request += metrics.request;
                self.aggregated_metrics[worker_id].response += metrics.response;
            }

            let now = self.clock.epoch_seconds();

            if now >= next_report_time {
                let elapsed_secs = (now - last_report_time) as f64;
                self.report_metrics(elapsed_secs);

                last_report_time = now;
                next_report_time = now + self.reporting_interval.as_secs();
            }
        }

        info!("Metrics collection shutting down");
    }

    /// Report aggregated metrics
    fn report_metrics(&self, elapsed_secs: f64) {
        let now = SystemTime::now();

        let aggregated = calc_aggregated_metrics(elapsed_secs, &self.aggregated_metrics);

        debug!("[METRICS] Cumulative metrics after {:.1}s", elapsed_secs);
        info!(
            "Network: send_ok={} send_fail={} poll_fail={} recv_fail={} recv_wouldblock={}",
            aggregated.network.num_successful_sends,
            aggregated.network.num_failed_sends,
            aggregated.network.num_failed_polls,
            aggregated.network.num_failed_recvs,
            aggregated.network.num_recv_wouldblock,
        );
        info!(
            "Requests: total={} ok={} bad={} runt={} jumbo={}",
            aggregated.total_requests,
            aggregated.requests.num_ok_requests,
            aggregated.requests.num_bad_requests,
            aggregated.requests.num_runt_requests,
            aggregated.requests.num_jumbo_requests
        );
        info!(
            "Responses: total={} bytes={:.1}MB",
            aggregated.responses.num_responses,
            aggregated.responses.num_bytes_sent as f64 / (1024.0 * 1024.0),
        );

        aggregated
            .responses
            .batch_timing
            .report()
            .iter()
            .filter(|r| r.count > 0)
            .for_each(|r| info!(" {}", r));

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
