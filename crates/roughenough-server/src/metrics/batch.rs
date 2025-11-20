use std::fmt::Display;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::metrics::latency::LatencyStats;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BatchTiming {
    // index - 1 == batch size, e.g.
    // batch_counts[0] == count of batches of size 1
    // batch_counts[1] == count of batches of size 2
    // etc...
    batch_counts: Vec<usize>,
    batch_latency: Vec<LatencyStats>
}

pub struct TimingReport {
    pub batch_size: u8,
    pub count: usize,
    pub min: Duration,
    pub p25: Duration,
    pub mean: Duration,
    pub median: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub p999: Duration,
}

impl BatchTiming {
    const MAX_BATCH_SIZE: usize = 64;
    const ENTRIES_PER_BATCH: usize = 1024;

    pub fn new() -> Self {
        Self {
            batch_counts: vec![0usize; Self::MAX_BATCH_SIZE],
            batch_latency: vec![LatencyStats::new(Self::ENTRIES_PER_BATCH); Self::MAX_BATCH_SIZE],
        }
    }
    
    pub fn merge(&mut self, rhs: &BatchTiming) {
        assert_eq!(self.batch_counts.len(), rhs.batch_counts.len());

        for i in 0..self.batch_counts.len() {
            self.batch_counts[i] += rhs.batch_counts[i];
            self.batch_latency[i].merge(&rhs.batch_latency[i]);
        }
    }

    pub fn record_batch(&mut self, batch_size: u8, elapsed: Duration) {
        self.batch_counts[batch_size as usize - 1] += 1;
        self.batch_latency[batch_size as usize - 1].record(elapsed);
    }

    pub fn report(&self) -> Vec<TimingReport> {
        let mut report = Vec::with_capacity(self.batch_counts.len());
        
        for (batch_size, stats) in self.batch_latency.iter().enumerate() {
            report.push(TimingReport {
                batch_size: batch_size as u8 + 1,
                count: stats.len(),
                min: stats.min(),
                p25: stats.p25(),
                mean: stats.mean(),
                median: stats.median(),
                p95: stats.p95(),
                p99: stats.p99(),
                p999: stats.p999(),
            })
        }

        report
    }

    pub fn reset(&mut self) {
        for i in 0..self.batch_counts.len() {
            self.batch_counts[i] = 0;
            self.batch_latency[i].reset();
        }
    }
}

impl Display for TimingReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "size: {}, count: {}, min: {:?}, p25: {:?}, mean: {:?}, median: {:?}, p95: {:?}, p99: {:?}, p999: {:?}",
            self.batch_size, self.count, self.min, self.p25, self.mean, self.median, self.p95, self.p99, self.p999
        )
    }
}
