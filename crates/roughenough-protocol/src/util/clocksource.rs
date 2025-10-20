use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
#[cfg(test)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use ClockSource::{FixedOffset, Mock, System};

/// A source of time.
#[derive(Debug, Clone)]
pub enum ClockSource {
    /// Clock source based on the system clock.
    System,

    /// Maintains a fixed number of seconds offset (positive or negative) from the system clock.
    /// Only for testing.
    FixedOffset(i16),

    /// Only for testing and benchmarking.
    Mock(Arc<AtomicU64>),
}

impl ClockSource {
    pub fn new_mock(now: u64) -> ClockSource {
        Mock(Arc::new(AtomicU64::new(now)))
    }
}

impl ClockSource {
    /// RFC 4.1.4: A timestamp is a representation of UTC time as a uint64 count of
    /// seconds since 00:00:00 on 1 January 1970 (the Unix epoch), assuming
    /// every day has 86400 seconds.
    ///
    /// Returns the number of seconds since the UNIX epoch. More specifically, returns the number
    /// of non-leap seconds since the start of 1970 UTC.
    pub fn epoch_seconds(&self) -> u64 {
        match self {
            System => match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(n) => n.as_secs(),
                Err(e) => panic!("SystemTime before UNIX EPOCH! {e:?}"),
            },
            FixedOffset(offset) => System.epoch_seconds().saturating_add_signed(*offset as i64),
            Mock(now) => now.load(SeqCst),
        }
    }

    /// Returns the number of seconds since the UNIX epoch.
    /// For test use only
    #[cfg(test)]
    pub fn now(&self) -> u64 {
        self.epoch_seconds()
    }

    /// Sets the current time of this Mock clock.
    /// For test use only.
    pub fn set_time(&mut self, now: u64) {
        match self {
            System => unreachable!(),
            FixedOffset(_) => unreachable!(),
            Mock(n) => n.store(now, SeqCst),
        }
    }

    /// Increases the current time of this Mock clock by the given duration.
    /// For test use only.
    #[cfg(test)]
    pub fn advance(&mut self, delta: Duration) {
        match self {
            System => unreachable!(),
            FixedOffset(_) => unreachable!(),
            Mock(n) => n.store(n.load(SeqCst) + delta.as_secs(), SeqCst),
        }
    }

    /// Decreases the current time of this Mock clock by the given duration.
    /// For test use only.
    #[cfg(test)]
    pub fn decrease(&mut self, delta: Duration) {
        match self {
            System => unreachable!(),
            FixedOffset(_) => unreachable!(),
            Mock(n) => n.store(n.load(SeqCst) - delta.as_secs(), SeqCst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now() {
        let timestamp = System.now();

        let clock = ClockSource::new_mock(timestamp);
        assert_eq!(clock.now(), timestamp);
        assert_eq!(clock.epoch_seconds(), timestamp);

        let clock = System;
        assert!(clock.now() >= timestamp);
        assert!(clock.epoch_seconds() >= timestamp);

        let clock = FixedOffset(10);
        assert!(clock.now() >= timestamp + 10);
        assert!(clock.epoch_seconds() >= timestamp + 10);
    }

    #[test]
    fn time_manipulation() {
        let now = System.now();
        let mut clock = ClockSource::new_mock(now - 1);
        assert_eq!(clock.now(), now - 1);

        // set_time should override the initial time value
        clock.set_time(now);

        clock.advance(Duration::from_secs(10));
        assert_eq!(clock.now(), now + 10);

        clock.decrease(Duration::from_secs(5));
        assert_eq!(clock.now(), now + 10 - 5);
    }

    #[test]
    fn cloned_clocks_share_underlying_time() {
        let now = System.now();
        let mut clock1 = ClockSource::new_mock(now - 1);

        let mut clock2 = clock1.clone();
        let clock3 = clock2.clone();
        assert_eq!(clock2.now(), now - 1);
        assert_eq!(clock3.now(), now - 1);

        clock1.set_time(now);

        assert_eq!(clock1.now(), now); // All three clocks
        assert_eq!(clock2.now(), now); // see the same
        assert_eq!(clock3.now(), now); // time value.

        clock2.set_time(now + 1);

        assert_eq!(clock1.now(), now + 1);
        assert_eq!(clock2.now(), now + 1);
        assert_eq!(clock3.now(), now + 1);
    }

    #[test]
    fn fixed_offset() {
        {
            let clock = FixedOffset(-10217);

            let fixed_time = clock.now();
            let system_time = System.now();

            assert_eq!(fixed_time, system_time - 10217);
        }

        {
            let clock = FixedOffset(1337);

            let system_time = System.now();
            let fixed_time = clock.now();

            assert_eq!(fixed_time, system_time + 1337);
        }
    }
}
