use std::fmt::Display;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::metrics::latency::LatencyHistogram;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BatchTiming {
    // index - 1 == batch size, e.g.
    // batch_latency[0] == histogram for batches of size 1
    // batch_latency[1] == histogram for batches of size 2
    // etc...
    batch_latency: Vec<LatencyHistogram>,
}

pub struct TimingReport {
    pub batch_size: u8,
    pub count: usize,
    pub min: Duration,
    pub p25: Duration,
    pub median: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub p999: Duration,
}

impl BatchTiming {
    const MAX_BATCH_SIZE: usize = 64;

    pub fn new() -> Self {
        Self {
            batch_latency: vec![LatencyHistogram::new(); Self::MAX_BATCH_SIZE],
        }
    }

    pub fn record_batch(&mut self, batch_size: u8, elapsed: Duration) {
        self.batch_latency[batch_size as usize - 1].record(elapsed);
    }

    /// Merge histograms from another BatchTiming into this one
    pub fn merge_from(&mut self, other: &BatchTiming) {
        assert_eq!(self.batch_latency.len(), other.batch_latency.len());

        for (lhs_hist, rhs_hist) in self
            .batch_latency
            .iter_mut()
            .zip(other.batch_latency.iter())
        {
            lhs_hist.merge_from(rhs_hist);
        }
    }

    pub fn report(&self) -> Vec<TimingReport> {
        let mut report = Vec::with_capacity(Self::MAX_BATCH_SIZE);

        for (batch_size, stats) in self.batch_latency.iter().enumerate() {
            report.push(TimingReport {
                batch_size: batch_size as u8 + 1,
                count: stats.len(),
                min: stats.min(),
                p25: stats.p25(),
                median: stats.median(),
                p95: stats.p95(),
                p99: stats.p99(),
                p999: stats.p999(),
            })
        }

        report
    }

    pub fn reset(&mut self) {
        for histogram in &mut self.batch_latency {
            histogram.reset();
        }
    }
}

impl Display for TimingReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "size: {}, count: {}, min: {:?}, p25: {:?}, median: {:?}, p95: {:?}, p99: {:?}, p999: {:?}",
            self.batch_size,
            self.count,
            self.min,
            self.p25,
            self.median,
            self.p95,
            self.p99,
            self.p999
        )
    }
}
