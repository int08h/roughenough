use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Bucketed histogram for latency measurements.
/// Uses exponential buckets covering sub-microsecond to multi-second latencies.
/// Memory: 32 buckets × 8 bytes = 256 bytes (plus min/max/count)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyHistogram {
    /// Count of samples in each bucket
    buckets: [u64; 32],
    /// Total number of samples recorded
    total_count: usize,
    /// Minimum observed latency
    min: Duration,
    /// Maximum observed latency
    max: Duration,
}

impl LatencyHistogram {
    const NUM_BUCKETS: usize = 32;

    /// Bucket boundaries in nanoseconds (lower bound of each bucket)
    /// Exponential scale with 1-2-5 pattern: 1μs, 2μs, 5μs, 10μs, 20μs, ..., 10s
    const BUCKET_BOUNDARIES_NS: [u64; Self::NUM_BUCKETS] = [
        0,               // [0, 1μs)
        1_000,           // [1μs, 2μs)
        2_000,           // [2μs, 5μs)
        5_000,           // [5μs, 10μs)
        10_000,          // [10μs, 20μs)
        20_000,          // [20μs, 50μs)
        50_000,          // [50μs, 100μs)
        100_000,         // [100μs, 200μs)
        200_000,         // [200μs, 500μs)
        500_000,         // [500μs, 1ms)
        1_000_000,       // [1ms, 2ms)
        2_000_000,       // [2ms, 5ms)
        5_000_000,       // [5ms, 10ms)
        10_000_000,      // [10ms, 20ms)
        20_000_000,      // [20ms, 50ms)
        50_000_000,      // [50ms, 100ms)
        100_000_000,     // [100ms, 200ms)
        200_000_000,     // [200ms, 500ms)
        500_000_000,     // [500ms, 1s)
        1_000_000_000,   // [1s, 2s)
        2_000_000_000,   // [2s, 5s)
        5_000_000_000,   // [5s, 10s)
        10_000_000_000,  // [10s, 20s)
        20_000_000_000,  // [20s, 50s)
        50_000_000_000,  // [50s, 100s)
        100_000_000_000, // [100s, ...)
        200_000_000_000,
        500_000_000_000,
        1_000_000_000_000,
        2_000_000_000_000,
        5_000_000_000_000,
        10_000_000_000_000,
    ];

    pub fn new() -> Self {
        Self {
            buckets: [0; Self::NUM_BUCKETS],
            total_count: 0,
            min: Duration::MAX,
            max: Duration::ZERO,
        }
    }

    /// Maps a duration to its bucket index
    fn duration_to_bucket(&self, duration: Duration) -> usize {
        let nanos: u64 = duration.as_nanos().try_into().unwrap();

        Self::BUCKET_BOUNDARIES_NS
            .binary_search(&nanos)
            .unwrap_or_else(|idx| if idx == 0 { 0 } else { idx - 1 })
    }

    /// Records a latency sample
    pub fn record(&mut self, duration: Duration) {
        let bucket_idx = self.duration_to_bucket(duration);
        self.buckets[bucket_idx] += 1;
        self.total_count += 1;

        if self.total_count == 1 {
            self.min = duration;
            self.max = duration;
        } else {
            self.min = self.min.min(duration);
            self.max = self.max.max(duration);
        }
    }

    /// Merges another histogram into this one
    pub fn merge_from(&mut self, other: &LatencyHistogram) {
        if other.total_count == 0 {
            return;
        }

        for i in 0..Self::NUM_BUCKETS {
            self.buckets[i] += other.buckets[i];
        }
        self.total_count += other.total_count;

        if self.total_count == other.total_count {
            // This histogram was empty
            self.min = other.min;
            self.max = other.max;
        } else {
            self.min = self.min.min(other.min);
            self.max = self.max.max(other.max);
        }
    }

    pub fn reset(&mut self) {
        self.buckets = [0; Self::NUM_BUCKETS];
        self.total_count = 0;
        self.min = Duration::MAX;
        self.max = Duration::ZERO;
    }

    pub fn len(&self) -> usize {
        self.total_count
    }

    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Estimates a percentile using linear interpolation within buckets
    pub fn percentile(&self, p: f64) -> Duration {
        assert!(
            p > 0.0 && p <= 1.0,
            "percentile must be between 0.0 and 1.0"
        );

        if self.total_count == 0 {
            return Duration::ZERO;
        }

        let target_rank = (p * self.total_count as f64) as u64;
        let mut cumulative = 0u64;

        for (bucket_idx, &count) in self.buckets.iter().enumerate() {
            if count == 0 {
                continue;
            }

            cumulative += count;

            if cumulative >= target_rank {
                // Target rank is in this bucket
                // Use midpoint of bucket as estimate
                let lower_bound_ns = Self::BUCKET_BOUNDARIES_NS[bucket_idx];
                let upper_bound_ns = if bucket_idx + 1 < Self::NUM_BUCKETS {
                    Self::BUCKET_BOUNDARIES_NS[bucket_idx + 1]
                } else {
                    // Last bucket - use max
                    return self.max;
                };

                // Linear interpolation within bucket
                let bucket_position = if cumulative == count {
                    // First samples in this bucket
                    0.5
                } else {
                    let samples_before = cumulative - count;
                    let rank_within_bucket = target_rank.saturating_sub(samples_before);
                    rank_within_bucket as f64 / count as f64
                };

                let interpolated_ns = lower_bound_ns as f64
                    + bucket_position * (upper_bound_ns - lower_bound_ns) as f64;

                return Duration::from_nanos(interpolated_ns as u64);
            }
        }

        unreachable!("target_rank should always be within histogram bounds");
    }

    pub fn min(&self) -> Duration {
        if self.total_count == 0 {
            Duration::ZERO
        } else {
            self.min
        }
    }

    pub fn max(&self) -> Duration {
        if self.total_count == 0 {
            Duration::ZERO
        } else {
            self.max
        }
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

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod histogram_tests {
    use super::*;

    #[test]
    fn new_initializes_empty() {
        let hist = LatencyHistogram::new();
        assert_eq!(hist.len(), 0);
        assert!(hist.is_empty());
    }

    #[test]
    fn records_samples_correctly() {
        let mut hist = LatencyHistogram::new();

        hist.record(Duration::from_micros(10));
        hist.record(Duration::from_millis(5));
        hist.record(Duration::from_millis(100));

        assert_eq!(hist.len(), 3);
        assert!(!hist.is_empty());
    }

    #[test]
    fn tracks_min_max() {
        let mut hist = LatencyHistogram::new();

        hist.record(Duration::from_micros(50));
        hist.record(Duration::from_micros(10));
        hist.record(Duration::from_micros(100));

        assert_eq!(hist.min(), Duration::from_micros(10));
        assert_eq!(hist.max(), Duration::from_micros(100));
    }

    #[test]
    fn merge_combines_histograms() {
        let mut hist1 = LatencyHistogram::new();
        hist1.record(Duration::from_micros(10));
        hist1.record(Duration::from_micros(20));

        let mut hist2 = LatencyHistogram::new();
        hist2.record(Duration::from_micros(30));
        hist2.record(Duration::from_micros(5));

        hist1.merge_from(&hist2);

        assert_eq!(hist1.len(), 4);
        assert_eq!(hist1.min(), Duration::from_micros(5));
        assert_eq!(hist1.max(), Duration::from_micros(30));
    }

    #[test]
    fn reset_clears_state() {
        let mut hist = LatencyHistogram::new();

        hist.record(Duration::from_millis(10));
        hist.record(Duration::from_millis(20));

        hist.reset();

        assert_eq!(hist.len(), 0);
        assert!(hist.is_empty());
    }

    #[test]
    fn percentile_estimates_correctly() {
        let mut hist = LatencyHistogram::new();

        // Add samples in a known distribution
        for _ in 0..50 {
            hist.record(Duration::from_micros(10));
        }
        for _ in 0..30 {
            hist.record(Duration::from_micros(20));
        }
        for _ in 0..20 {
            hist.record(Duration::from_micros(30));
        }

        // p50 should be around 10-20μs (50th sample is in first group)
        let p50 = hist.median();
        assert!(p50 >= Duration::from_micros(10));
        assert!(p50 <= Duration::from_micros(20));

        // p95 should be in the 30μs bucket
        let p95 = hist.p95();
        assert!(p95 >= Duration::from_micros(20));
        assert!(p95 <= Duration::from_micros(50));
    }

    #[test]
    fn bucket_mapping_works() {
        let hist = LatencyHistogram::new();

        // Test various durations map to expected buckets
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(500)), 0); // [0, 1μs)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(1)), 1); // [1μs, 2μs)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(3)), 2); // [2μs, 5μs)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(7)), 3); // [5μs, 10μs)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(15)), 4); // [10μs, 20μs)
        assert_eq!(hist.duration_to_bucket(Duration::from_millis(1)), 10); // [1ms, 2ms)
        assert_eq!(hist.duration_to_bucket(Duration::from_millis(3)), 11); // [2ms, 5ms)
        assert_eq!(hist.duration_to_bucket(Duration::from_secs(1)), 19); // [1s, 2s)
    }
}
