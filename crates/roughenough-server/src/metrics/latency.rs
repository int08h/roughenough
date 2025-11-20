use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Tracks latency measurements, acting as a circular buffer (overwriting prior values)
/// once more than `capacity` samples are recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    samples: Vec<Duration>,
    index: usize,
    capacity: usize,
}

impl LatencyStats {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "Capacity must be greater than 0");

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

    pub fn merge(&mut self, other: &LatencyStats) {
        let olen = other.len();
        for &sample in other.samples[..olen].iter() {
            self.record(sample);
        }
    }

    pub fn reset(&mut self) {
        self.index = 0;
    }

    pub fn len(&self) -> usize {
        self.index.min(self.capacity)
    }

    pub fn is_empty(&self) -> bool {
        self.index == 0
    }
    
    pub fn percentile(&self, p: f64) -> Duration {
        assert!(
            p > 0.0 && p <= 1.0,
            "percentile must be between 0.0 and 1.0"
        );

        if self.index == 0 {
            return Duration::ZERO;
        }

        let len = self.len();
        let mut copy = self.samples[..len].to_vec();
        copy.sort_unstable();

        // rank in [0, end]
        let rank = p * (len as f64 - 1.0);
        let idx = rank.round() as usize;
        copy[idx]
    }

    pub fn mean(&self) -> Duration {
        if self.index == 0 {
            return Duration::ZERO;
        }
        let slice = &self.samples[..self.len()];
        let len: u32 = slice.len().try_into().unwrap();
        slice.iter().sum::<Duration>() / len
    }

    pub fn min(&self) -> Duration {
        let slice = &self.samples[..self.len()];
        *slice.iter().min().unwrap_or(&Duration::ZERO)
    }

    pub fn max(&self) -> Duration {
        let slice = &self.samples[..self.len()];
        *slice.iter().max().unwrap_or(&Duration::MAX)
    }

    pub fn p25(&self) -> Duration {
        self.percentile(0.25)
    }

    pub fn median(&self) -> Duration {
        self.percentile(0.5)
    }

    pub fn p95(&self) -> Duration {
        self.percentile(0.95)
    }

    pub fn p99(&self) -> Duration {
        self.percentile(0.99)
    }

    pub fn p999(&self) -> Duration {
        self.percentile(0.999)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn new_initializes_with_zero_durations() {
        let cap = 7;
        let stats = LatencyStats::new(cap);

        assert_eq!(stats.len(), 0);
        assert_eq!(stats.samples.len(), cap);
        assert!(stats.samples.iter().all(|d| *d == Duration::ZERO));
    }

    #[test]
    fn record_wraps_around_as_circular_buffer() {
        let mut stats = LatencyStats::new(3);

        stats.record(Duration::from_millis(10)); // index 0
        stats.record(Duration::from_millis(20)); // index 1
        stats.record(Duration::from_millis(30)); // index 2
        //
        // Next writes should wrap and overwrite from index 0
        //
        stats.record(Duration::from_millis(40)); // overwrites index 0
        stats.record(Duration::from_millis(50)); // overwrites index 1

        // The buffer should now contain the last 3 values: 40, 50, 30
        let mut values = stats.samples.clone();
        values.sort_unstable();

        assert_eq!(
            values,
            vec![
                Duration::from_millis(30),
                Duration::from_millis(40),
                Duration::from_millis(50)
            ]
        );
    }

    #[test]
    fn reset_sets_all_durations_to_zero() {
        let mut stats = LatencyStats::new(3);
        stats.record(Duration::from_millis(10));
        stats.record(Duration::from_millis(20));
        stats.record(Duration::from_millis(30));

        assert!(stats.samples.iter().all(|d| *d != Duration::ZERO));
        assert_eq!(stats.mean(), Duration::from_millis(20));

        stats.reset();

        assert_eq!(stats.len(), 0);
        assert_eq!(stats.mean(), Duration::from_nanos(0));
    }

    #[test]
    fn percentile_uses_sorted_copy_and_bounds() {
        let mut stats = LatencyStats::new(5);

        // Order is intentionally shuffled
        let values = [
            Duration::from_millis(50),
            Duration::from_millis(10),
            Duration::from_millis(30),
            Duration::from_millis(40),
            Duration::from_millis(20),
        ];

        for v in values {
            stats.record(v);
        }

        // Sorted: [10, 20, 30, 40, 50]
        assert_eq!(stats.percentile(0.21), Duration::from_millis(20));
        assert_eq!(stats.percentile(0.5), Duration::from_millis(30));
        assert_eq!(stats.percentile(1.0), Duration::from_millis(50));
    }

    #[test]
    #[should_panic(expected = "percentile must be between 0.0 and 1.0")]
    fn percentile_panics_on_zero() {
        let stats = LatencyStats::new(1);
        stats.percentile(0.0);
    }

    #[test]
    #[should_panic(expected = "percentile must be between 0.0 and 1.0")]
    fn percentile_panics_above_one() {
        let stats = LatencyStats::new(1);
        stats.percentile(1.000_000_1);
    }

    #[test]
    fn mean_is_average_of_samples() {
        let mut stats = LatencyStats::new(4);

        stats.record(Duration::from_millis(10));
        stats.record(Duration::from_millis(20));
        stats.record(Duration::from_millis(30));
        stats.record(Duration::from_millis(40));

        // Mean = (10 + 20 + 30 + 40) / 4 = 25
        assert_eq!(stats.mean(), Duration::from_millis(25));
    }

    #[test]
    fn high_percentile_helpers_delegate_to_percentile() {
        let mut stats = LatencyStats::new(5);

        // Sorted: [10, 20, 30, 40, 50]
        let values = [
            Duration::from_millis(50),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
            Duration::from_millis(40),
        ];
        for v in values {
            stats.record(v);
        }

        // For 5 elements:
        // idx = round(5 * p), clamped to 0..=4
        // p95  -> round(4.75) = 5 -> 50
        // p99  -> round(4.95) = 5 -> 50
        // p999 -> round(4.995) = 5 -> 50
        assert_eq!(stats.p95(), Duration::from_millis(50));
        assert_eq!(stats.p99(), Duration::from_millis(50));
        assert_eq!(stats.p999(), Duration::from_millis(50));
    }
}
