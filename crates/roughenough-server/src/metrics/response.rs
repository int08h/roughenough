use crate::metrics::batch::BatchTiming;
use serde::{Deserialize, Serialize};
use std::ops::AddAssign;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetrics {
    pub num_responses: usize,
    pub num_bytes_sent: usize,
    pub batch_timing: BatchTiming,
}

impl Default for ResponseMetrics {
    fn default() -> Self {
        Self {
            num_responses: 0,
            num_bytes_sent: 0,
            batch_timing: BatchTiming::new(),
        }
    }
}

impl ResponseMetrics {
    const MAX_BATCH_SIZE: usize = 64;

    pub fn record_batch(&mut self, batch_size: u8, elapsed: Duration) {
        debug_assert!(
            batch_size > 0 && batch_size <= Self::MAX_BATCH_SIZE as u8,
            "Invalid batch size: {batch_size}"
        );

        self.num_responses += batch_size as usize;
        self.batch_timing.record_batch(batch_size, elapsed);
    }

    pub fn add_bytes_sent(&mut self, num_bytes: usize) {
        self.num_bytes_sent += num_bytes;
    }

    pub fn reset_metrics(&mut self) {
        self.num_responses = 0;
        self.num_bytes_sent = 0;
        self.batch_timing.reset();
    }
}

impl AddAssign for ResponseMetrics {
    fn add_assign(&mut self, rhs: Self) {
        self.num_responses += rhs.num_responses;
        self.num_bytes_sent += rhs.num_bytes_sent;
        self.batch_timing.merge(&rhs.batch_timing);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::time::Duration;

    fn get_batch_count(metrics: &ResponseMetrics, batch_size: u8) -> usize {
        metrics
            .batch_timing
            .report()
            .into_iter()
            .find(|r| r.batch_size == batch_size)
            .map(|r| r.count)
            .unwrap_or(0)
    }

    #[test]
    fn default_initializes_zero_counters_and_batch_timing() {
        let metrics = ResponseMetrics::default();

        assert_eq!(metrics.num_responses, 0);
        assert_eq!(metrics.num_bytes_sent, 0);

        // All batch counts should be zero after default construction
        for report in metrics.batch_timing.report() {
            assert_eq!(report.count, 0);
        }
    }

    #[test]
    fn record_batch_increments_response_count_and_updates_timing() {
        let mut metrics = ResponseMetrics::default();
        let elapsed = Duration::from_millis(5);

        metrics.record_batch(4, elapsed);

        assert_eq!(metrics.num_responses, 4);

        // Report should reflect exactly one batch of size 4
        assert_eq!(get_batch_count(&metrics, 4), 1);
    }

    #[test]
    fn add_bytes_sent_accumulates_total_bytes() {
        let mut metrics = ResponseMetrics::default();

        metrics.add_bytes_sent(100);
        metrics.add_bytes_sent(250);

        assert_eq!(metrics.num_bytes_sent, 350);
    }

    #[test]
    fn reset_metrics_clears_counters_and_batch_timing() {
        let mut metrics = ResponseMetrics::default();

        // Populate with some data
        metrics.record_batch(2, Duration::from_millis(3));
        metrics.record_batch(3, Duration::from_millis(4));
        metrics.add_bytes_sent(1024);

        assert_eq!(metrics.num_responses, 5);
        assert_eq!(metrics.num_bytes_sent, 1024);

        metrics.reset_metrics();

        assert_eq!(metrics.num_responses, 0);
        assert_eq!(metrics.num_bytes_sent, 0);

        // After reset, all batch counts should be zero again
        for report in metrics.batch_timing.report() {
            assert_eq!(report.count, 0);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn record_batch_with_invalid_size_panics_in_debug() {
        let mut metrics = ResponseMetrics::default();

        // batch_size == 0 should trigger the debug_assert
        let result_zero = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            metrics.record_batch(0, Duration::from_millis(1));
        }));
        assert!(result_zero.is_err(), "record_batch(0, ..) should panic in debug builds");

        // batch_size > MAX_BATCH_SIZE should also trigger the debug_assert
        let result_too_large = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            metrics.record_batch((ResponseMetrics::MAX_BATCH_SIZE + 1) as u8, Duration::from_millis(1));
        }));
        assert!(
            result_too_large.is_err(),
            "record_batch(>MAX_BATCH_SIZE, ..) should panic in debug builds"
        );
    }

    #[test]
    fn add_assign_sums_counters_and_merges_batch_timing() {
        let mut lhs = ResponseMetrics::default();
        let mut rhs = ResponseMetrics::default();

        // Populate lhs
        lhs.record_batch(1, Duration::from_millis(10));
        lhs.record_batch(2, Duration::from_millis(20));
        lhs.add_bytes_sent(100);

        // Populate rhs
        rhs.record_batch(1, Duration::from_millis(30));
        rhs.record_batch(3, Duration::from_millis(40));
        rhs.add_bytes_sent(50);

        // num_responses is total number of responses across both
        assert_eq!(lhs.num_responses, 3);
        assert_eq!(rhs.num_responses, 4);

        lhs += rhs;

        // Counters should be summed
        assert_eq!(lhs.num_responses, 7);
        assert_eq!(lhs.num_bytes_sent, 150);

        // Batch timing should be merged:
        // - batch size 1: 1 (lhs) + 1 (rhs) = 2
        // - batch size 2: 1 (lhs)
        // - batch size 3: 1 (rhs)
        assert_eq!(get_batch_count(&lhs, 1), 2);
        assert_eq!(get_batch_count(&lhs, 2), 1);
        assert_eq!(get_batch_count(&lhs, 3), 1);
    }

    #[test]
    fn add_assign_with_default_rhs_does_not_change_lhs() {
        let mut lhs = ResponseMetrics::default();
        lhs.record_batch(4, Duration::from_millis(5));
        lhs.add_bytes_sent(256);

        let snapshot_before = (lhs.num_responses, lhs.num_bytes_sent, get_batch_count(&lhs, 4));

        let rhs = ResponseMetrics::default();
        lhs += rhs;

        let snapshot_after = (lhs.num_responses, lhs.num_bytes_sent, get_batch_count(&lhs, 4));
        assert_eq!(snapshot_before, snapshot_after);
    }
}

