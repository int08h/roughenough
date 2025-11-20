use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Circular buffer for tracking latency measurements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    samples: Vec<Duration>,
    index: usize,
    capacity: usize,
}

impl LatencyStats {
    pub fn new(capacity: usize) -> Self {
        Self {
            samples: vec![Duration::ZERO; capacity],
            index: 0,
            capacity,
        }
    }

    pub fn record(&mut self, duration: Duration) {
        self.samples[self.index % self.capacity] = duration;
        self.index = self.index.wrapping_add(1);
    }

    pub fn len(&self) -> usize {
        self.capacity
    }

    pub fn clear(&mut self) {
        self.index = 0;
        self.samples.clear();
        self.samples.resize(self.capacity, Duration::ZERO);
    }

    pub fn percentile(&mut self, p: f64) -> Duration {
        let mut copy = self.samples.clone();
        copy.sort_unstable();
        let idx = ((self.capacity as f64 * p).floor() as usize).min(self.capacity - 1);
        copy[idx]
    }

    pub fn mean(&mut self) -> Duration {
        self.samples.iter().sum::<Duration>() / self.samples.len() as u32
    }

    pub fn median(&mut self) -> Duration {
        self.percentile(0.5)
    }

    pub fn p95(&mut self) -> Duration {
        self.percentile(0.95)
    }

    pub fn p99(&mut self) -> Duration {
        self.percentile(0.99)
    }

    pub fn p999(&mut self) -> Duration {
        self.percentile(0.999)
    }
}