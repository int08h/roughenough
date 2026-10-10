pub mod aggregator;
pub mod snapshot;
pub mod types;

/// When the next periodic metrics report is due, in wall-clock epoch seconds
#[derive(Debug)]
pub(crate) struct ReportSchedule {
    interval: u64,
    last_report: u64,
    next_report: u64,
}

impl ReportSchedule {
    pub(crate) fn new(now: u64, interval: u64) -> Self {
        Self {
            interval,
            last_report: now,
            next_report: now + interval,
        }
    }

    /// Returns the seconds since the last report if one is due at `now`.
    pub(crate) fn poll(&mut self, now: u64) -> Option<u64> {
        // If the clock steps backwards, restart from `now` rather than stall
        // until the clock regains the old deadline
        if now < self.last_report {
            *self = Self::new(now, self.interval);
            return None;
        }

        if now < self.next_report {
            return None;
        }

        let elapsed = now - self.last_report;
        *self = Self::new(now, self.interval);
        Some(elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_reports_once_per_interval() {
        let mut schedule = ReportSchedule::new(1000, 60);

        assert_eq!(schedule.poll(1000), None);
        assert_eq!(schedule.poll(1059), None);
        assert_eq!(schedule.poll(1061), Some(61));
        assert_eq!(schedule.poll(1100), None);
        assert_eq!(schedule.poll(1121), Some(60));
    }

    #[test]
    fn schedule_survives_backward_clock_step() {
        let mut schedule = ReportSchedule::new(10_000, 60);

        // Stepping back an hour does not report
        assert_eq!(schedule.poll(6_400), None);

        // Reports resume one interval after the step, not after the clock
        // regains 10_060
        assert_eq!(schedule.poll(6_459), None);
        assert_eq!(schedule.poll(6_460), Some(60));
    }
}
