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

    /// Threshold where we switch from linear to exponential buckets (2^15 = 32768ns ~ 32.8us)
    /// Linear region: 16 buckets of 2^11 ns (~2.05us) each, covering 0-32.8us
    /// Exponential region: 16 power-of-2 buckets covering 32.8us to 1s+
    const LINEAR_THRESHOLD_NS: u64 = 1 << 15; // 32768

    /// Bucket boundaries in nanoseconds (lower bound of each bucket)
    /// Hybrid scheme: ~2us linear buckets for 0-32.8us, then power-of-2 above
    const BUCKET_BOUNDARIES_NS: [u64; Self::NUM_BUCKETS] = [
        // Linear region: 2048ns (~2us) buckets
        0,           // [0, 2.05us)
        1 << 11,     // [2.05us, 4.1us)
        2 << 11,     // [4.1us, 6.1us)
        3 << 11,     // [6.1us, 8.2us)
        4 << 11,     // [8.2us, 10.2us)
        5 << 11,     // [10.2us, 12.3us)
        6 << 11,     // [12.3us, 14.3us)
        7 << 11,     // [14.3us, 16.4us)
        8 << 11,     // [16.4us, 18.4us)
        9 << 11,     // [18.4us, 20.5us)
        10 << 11,    // [20.5us, 22.5us)
        11 << 11,    // [22.5us, 24.6us)
        12 << 11,    // [24.6us, 26.6us)
        13 << 11,    // [26.6us, 28.7us)
        14 << 11,    // [28.7us, 30.7us)
        15 << 11,    // [30.7us, 32.8us)
        // Exponential region: power-of-2 buckets
        1 << 15,     // [32.8us, 65.5us)
        1 << 16,     // [65.5us, 131us)
        1 << 17,     // [131us, 262us)
        1 << 18,     // [262us, 524us)
        1 << 19,     // [524us, 1.05ms)
        1 << 20,     // [1.05ms, 2.1ms)
        1 << 21,     // [2.1ms, 4.2ms)
        1 << 22,     // [4.2ms, 8.4ms)
        1 << 23,     // [8.4ms, 16.8ms)
        1 << 24,     // [16.8ms, 33.6ms)
        1 << 25,     // [33.6ms, 67.1ms)
        1 << 26,     // [67.1ms, 134ms)
        1 << 27,     // [134ms, 268ms)
        1 << 28,     // [268ms, 537ms)
        1 << 29,     // [537ms, 1.07s)
        1 << 30,     // [1.07s, +inf)
    ];

    pub fn new() -> Self {
        Self {
            buckets: [0; Self::NUM_BUCKETS],
            total_count: 0,
            min: Duration::MAX,
            max: Duration::ZERO,
        }
    }

    /// Maps a duration to its bucket index using hybrid linear/power-of-2 scheme.
    /// Linear region (0-32.8us): O(1) via integer division
    /// Exponential region (32.8us+): O(1) via leading_zeros
    fn duration_to_bucket(&self, duration: Duration) -> usize {
        let nanos: u64 = duration.as_nanos().try_into().unwrap();

        if nanos < Self::LINEAR_THRESHOLD_NS {
            // Linear region: direct calculation via right shift (division by 2048)
            (nanos >> 11) as usize
        } else {
            // Exponential region: O(1) via leading_zeros
            // For nanos >= 2^15: bucket = 64 - leading_zeros(nanos), clamped to 31
            let bucket = 64 - nanos.leading_zeros();
            bucket.min(31) as usize
        }
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
        // 10us -> bucket 4 [8.2us, 10.2us)
        // 20us -> bucket 9 [18.4us, 20.5us)
        // 30us -> bucket 14 [28.7us, 30.7us)
        for _ in 0..50 {
            hist.record(Duration::from_micros(10));
        }
        for _ in 0..30 {
            hist.record(Duration::from_micros(20));
        }
        for _ in 0..20 {
            hist.record(Duration::from_micros(30));
        }

        // p50 should be in the 10us bucket [8.2us, 10.2us)
        let p50 = hist.median();
        assert!(p50 >= Duration::from_micros(8));
        assert!(p50 <= Duration::from_micros(11));

        // p95 should be in the 30us bucket [28.7us, 30.7us)
        let p95 = hist.p95();
        assert!(p95 >= Duration::from_micros(20));
        assert!(p95 <= Duration::from_micros(32));
    }

    #[test]
    fn bucket_mapping_works() {
        let hist = LatencyHistogram::new();

        // Test linear region (0-32.8us, ~2us buckets via right shift by 11)
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(500)), 0); // [0, 2.05us)
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(2047)), 0); // [0, 2.05us)
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(2048)), 1); // [2.05us, 4.1us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(3)), 1); // [2.05us, 4.1us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(5)), 2); // [4.1us, 6.1us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(11)), 5); // [10.2us, 12.3us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(19)), 9); // [18.4us, 20.5us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(30)), 14); // [28.7us, 30.7us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(32)), 15); // [30.7us, 32.8us)

        // Test exponential region (32.8us+, power-of-2 via leading_zeros)
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(32768)), 16); // [32.8us, 65.5us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(50)), 16); // [32.8us, 65.5us)
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(65536)), 17); // [65.5us, 131us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(100)), 17); // [65.5us, 131us)
        assert_eq!(hist.duration_to_bucket(Duration::from_millis(1)), 20); // [524us, 1.05ms)
        assert_eq!(hist.duration_to_bucket(Duration::from_millis(3)), 22); // [2.1ms, 4.2ms)
        assert_eq!(hist.duration_to_bucket(Duration::from_secs(1)), 30); // [537ms, 1.07s)
        assert_eq!(hist.duration_to_bucket(Duration::from_secs(10)), 31); // [1.07s, +inf) clamped
    }
}
