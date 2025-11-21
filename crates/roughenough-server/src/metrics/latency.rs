use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Bucketed histogram for approximate latency measurements.
///
/// Uses linear 4.1us-wide buckets for the 0-1000us range, and exponential buckets
/// for latencies >918us.
///
/// Memory: 256 buckets x 8 bytes = 2048 bytes (plus count)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyHistogram {
    /// Count of samples in each bucket
    buckets: Vec<u64>,
    /// Total number of samples recorded
    total_count: usize,
}

impl LatencyHistogram {
    const NUM_BUCKETS: usize = 256;
    const NUM_LINEAR_BUCKETS: usize = 224;

    /// Bucket width for linear region: 2^12 = 4096ns (~4.1us)
    const LINEAR_BUCKET_WIDTH_SHIFT: u32 = 12;

    /// Linear threshold: 224 * 4096 = 917,504ns (~918us)
    /// Linear region: 224 buckets of ~4.1us each, covering 0-918us
    /// Exponential region: 32 power-of-2 buckets covering 918us to seconds+
    const LINEAR_THRESHOLD_NS: u64 =
        (Self::NUM_LINEAR_BUCKETS as u64) << Self::LINEAR_BUCKET_WIDTH_SHIFT;

    /// First exponential bucket boundary: 2^20 = 1,048,576ns (~1.05ms)
    const EXPONENTIAL_START_BIT: u32 = 20;

    pub fn new() -> Self {
        Self {
            buckets: vec![0; Self::NUM_BUCKETS],
            total_count: 0,
        }
    }

    /// Returns the lower bound in nanoseconds for a given bucket index
    #[inline]
    fn bucket_lower_bound_ns(bucket_idx: usize) -> u64 {
        if bucket_idx < Self::NUM_LINEAR_BUCKETS {
            (bucket_idx as u64) << Self::LINEAR_BUCKET_WIDTH_SHIFT
        } else if bucket_idx == Self::NUM_LINEAR_BUCKETS {
            // First exponential bucket starts at linear threshold
            Self::LINEAR_THRESHOLD_NS
        } else {
            let exp_idx = bucket_idx - Self::NUM_LINEAR_BUCKETS;
            1u64 << (Self::EXPONENTIAL_START_BIT + exp_idx as u32)
        }
    }

    /// Returns the upper bound in nanoseconds for a given bucket index
    #[inline]
    fn bucket_upper_bound_ns(bucket_idx: usize) -> u64 {
        if bucket_idx + 1 >= Self::NUM_BUCKETS {
            u64::MAX
        } else if bucket_idx < Self::NUM_LINEAR_BUCKETS {
            ((bucket_idx + 1) as u64) << Self::LINEAR_BUCKET_WIDTH_SHIFT
        } else {
            let exp_idx = (bucket_idx + 1) - Self::NUM_LINEAR_BUCKETS;
            1u64 << (Self::EXPONENTIAL_START_BIT + exp_idx as u32)
        }
    }

    /// Maps a duration to its bucket index.
    #[inline]
    fn duration_to_bucket(&self, duration: Duration) -> usize {
        let nanos: u64 = duration.as_nanos().try_into().unwrap_or(u64::MAX);

        if nanos < Self::LINEAR_THRESHOLD_NS {
            // Linear region: direct calculation via right shift
            (nanos >> Self::LINEAR_BUCKET_WIDTH_SHIFT) as usize
        } else {
            // Exponential region: O(1) via leading_zeros
            let bit_pos = 63u32.saturating_sub(nanos.leading_zeros());
            let exp_bucket = bit_pos.saturating_sub(Self::EXPONENTIAL_START_BIT) as usize;
            (Self::NUM_LINEAR_BUCKETS + exp_bucket).min(Self::NUM_BUCKETS - 1)
        }
    }

    /// Records a latency sample
    pub fn record(&mut self, duration: Duration) {
        let bucket_idx = self.duration_to_bucket(duration);
        self.buckets[bucket_idx] += 1;
        self.total_count += 1;
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
    }

    pub fn reset(&mut self) {
        self.buckets.fill(0);
        self.total_count = 0;
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
                let lower_bound_ns = Self::bucket_lower_bound_ns(bucket_idx);
                let upper_bound_ns = Self::bucket_upper_bound_ns(bucket_idx);

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
                    + bucket_position * upper_bound_ns.saturating_sub(lower_bound_ns) as f64;

                return Duration::from_nanos(interpolated_ns as u64);
            }
        }

        unreachable!("target_rank should always be within histogram bounds");
    }

    /// Returns the lower bound of the first non-empty bucket
    pub fn min(&self) -> Duration {
        if self.total_count == 0 {
            return Duration::ZERO;
        }
        for (bucket_idx, &count) in self.buckets.iter().enumerate() {
            if count > 0 {
                return Duration::from_nanos(Self::bucket_lower_bound_ns(bucket_idx));
            }
        }
        Duration::ZERO
    }

    /// Returns the upper bound of the last non-empty bucket
    pub fn max(&self) -> Duration {
        if self.total_count == 0 {
            return Duration::ZERO;
        }
        for (bucket_idx, &count) in self.buckets.iter().enumerate().rev() {
            if count > 0 {
                let upper = Self::bucket_upper_bound_ns(bucket_idx);
                // Clamp to avoid overflow when converting u64::MAX
                return Duration::from_nanos(upper.min(u64::MAX - 1));
            }
        }
        Duration::ZERO
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
    fn min_max_return_bucket_bounds() {
        let mut hist = LatencyHistogram::new();

        hist.record(Duration::from_micros(50));
        hist.record(Duration::from_micros(10));
        hist.record(Duration::from_micros(100));

        // min() returns lower bound of first non-empty bucket
        // 10us is in bucket 2 [8192ns, 12288ns), so min() = 8192ns
        assert_eq!(hist.min(), Duration::from_nanos(8192));

        // max() returns upper bound of last non-empty bucket
        // 100us is in bucket 24 [98304ns, 102400ns), so max() = 102400ns
        assert_eq!(hist.max(), Duration::from_nanos(102400));
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
        // 5us is in bucket 1 [4096ns, 8192ns), so min() = 4096ns
        assert_eq!(hist1.min(), Duration::from_nanos(4096));
        // 30us is in bucket 7 [28672ns, 32768ns), so max() = 32768ns
        assert_eq!(hist1.max(), Duration::from_nanos(32768));
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
        // With ~4.1us buckets:
        // 10us -> bucket 2 [8.2us, 12.3us)
        // 20us -> bucket 4 [16.4us, 20.5us)
        // 30us -> bucket 7 [28.7us, 32.8us)
        for _ in 0..50 {
            hist.record(Duration::from_micros(10));
        }
        for _ in 0..30 {
            hist.record(Duration::from_micros(20));
        }
        for _ in 0..20 {
            hist.record(Duration::from_micros(30));
        }

        // p50 should be in the 10us bucket [8.2us, 12.3us)
        let p50 = hist.median();
        assert!(p50 >= Duration::from_micros(8));
        assert!(p50 <= Duration::from_micros(13));

        // p95 should be in the 30us bucket [28.7us, 32.8us)
        let p95 = hist.p95();
        assert!(p95 >= Duration::from_micros(20));
        assert!(p95 <= Duration::from_micros(33));
    }

    #[test]
    fn bucket_mapping_linear_region() {
        let hist = LatencyHistogram::new();

        // Linear region: 0-918us with ~4.1us buckets (shift by 12, divide by 4096)
        // Bucket 0: [0, 4096ns) = [0, 4.1us)
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(0)), 0);
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(4095)), 0);

        // Bucket 1: [4096, 8192ns) = [4.1us, 8.2us)
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(4096)), 1);
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(5)), 1);

        // Bucket 2: [8192, 12288ns) = [8.2us, 12.3us)
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(10)), 2);

        // Test various points in the linear region
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(50)), 12); // 50000/4096 = 12
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(100)), 24); // 100000/4096 = 24
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(500)), 122); // 500000/4096 = 122
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(900)), 219); // 900000/4096 = 219

        // Last linear bucket (223): ends at 917504ns (~918us)
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(917503)), 223);
    }

    #[test]
    fn bucket_mapping_exponential_region() {
        let hist = LatencyHistogram::new();

        // Exponential region starts at bucket 224 (>=918us)
        // Bucket 224: [918us, 2.1ms) - covers gap and first exponential range
        assert_eq!(hist.duration_to_bucket(Duration::from_nanos(917504)), 224);
        assert_eq!(hist.duration_to_bucket(Duration::from_micros(950)), 224);
        assert_eq!(hist.duration_to_bucket(Duration::from_millis(1)), 224);

        // Bucket 225: [2.1ms, 4.2ms) - 2^21 boundary
        assert_eq!(
            hist.duration_to_bucket(Duration::from_nanos(2_097_152)),
            225
        );
        assert_eq!(hist.duration_to_bucket(Duration::from_millis(3)), 225);

        // Bucket 226: [4.2ms, 8.4ms) - 2^22 boundary
        assert_eq!(hist.duration_to_bucket(Duration::from_millis(5)), 226);

        // Higher latencies
        // 100ms = 100,000,000ns, between 2^26 (67M) and 2^27 (134M), so bit_pos=26, bucket=224+6=230
        assert_eq!(hist.duration_to_bucket(Duration::from_millis(100)), 230);
        // 1s = 1,000,000,000ns, between 2^29 (537M) and 2^30 (1.07B), so bit_pos=29, bucket=224+9=233
        assert_eq!(hist.duration_to_bucket(Duration::from_secs(1)), 233);

        // Very high latencies clamp to bucket 255
        // Bucket 255 starts at 2^51 ns (~26 days), so need very large values
        assert_eq!(
            hist.duration_to_bucket(Duration::from_secs(86400 * 30)),
            255
        ); // 30 days
    }

    #[test]
    fn bucket_bounds_linear() {
        // Test linear bucket bounds
        assert_eq!(LatencyHistogram::bucket_lower_bound_ns(0), 0);
        assert_eq!(LatencyHistogram::bucket_upper_bound_ns(0), 4096);

        assert_eq!(LatencyHistogram::bucket_lower_bound_ns(1), 4096);
        assert_eq!(LatencyHistogram::bucket_upper_bound_ns(1), 8192);

        assert_eq!(LatencyHistogram::bucket_lower_bound_ns(223), 223 * 4096);
        assert_eq!(LatencyHistogram::bucket_upper_bound_ns(223), 224 * 4096);
    }

    #[test]
    fn bucket_bounds_exponential() {
        // First exponential bucket starts at linear threshold
        assert_eq!(
            LatencyHistogram::bucket_lower_bound_ns(224),
            224 * 4096 // 917504
        );
        assert_eq!(
            LatencyHistogram::bucket_upper_bound_ns(224),
            1 << 21 // 2097152
        );

        // Subsequent exponential buckets use power-of-2
        assert_eq!(LatencyHistogram::bucket_lower_bound_ns(225), 1 << 21);
        assert_eq!(LatencyHistogram::bucket_upper_bound_ns(225), 1 << 22);

        // Last bucket
        assert_eq!(LatencyHistogram::bucket_lower_bound_ns(255), 1 << 51);
        assert_eq!(LatencyHistogram::bucket_upper_bound_ns(255), u64::MAX);
    }

    #[test]
    fn linear_region_provides_good_precision() {
        // Verify that the linear region covers 10us-1000us with ~4us precision
        let hist = LatencyHistogram::new();

        // 10us should map to a specific bucket
        let bucket_10us = hist.duration_to_bucket(Duration::from_micros(10));
        let bucket_14us = hist.duration_to_bucket(Duration::from_micros(14));
        // With ~4us buckets, 10us and 14us should be in different buckets
        assert_ne!(bucket_10us, bucket_14us);

        // 100us should still be in linear region with good precision
        let bucket_100us = hist.duration_to_bucket(Duration::from_micros(100));
        let bucket_104us = hist.duration_to_bucket(Duration::from_micros(104));
        assert_ne!(bucket_100us, bucket_104us);

        // 500us should still be in linear region
        let bucket_500us = hist.duration_to_bucket(Duration::from_micros(500));
        assert!(bucket_500us < 224); // Still in linear region

        // 900us should be near the end of linear region
        let bucket_900us = hist.duration_to_bucket(Duration::from_micros(900));
        assert!(bucket_900us < 224); // Still in linear region
    }
}
