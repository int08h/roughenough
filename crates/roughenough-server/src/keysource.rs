use std::sync::{Arc, Mutex};
use std::time::Duration;

use roughenough_keys::longterm::LongTermIdentity;
use roughenough_keys::online::onlinekey::OnlineKey;
use roughenough_keys::seed::SeedBackend;
use roughenough_protocol::tags::{PublicKey, Version};
use roughenough_protocol::util::ClockSource;

/// A thread-safe source of `OnlineKey`s for Workers. All generated `OnlineKey`s share a clock,
/// validity length, and long-term identity.
#[derive(Clone)]
pub struct KeySource {
    /// Long-term server identity
    identity: Arc<Mutex<LongTermIdentity>>,

    /// How long generated OnlineKey's remain good
    validity_length: Duration,

    /// Time source
    clock_source: ClockSource,
}

unsafe impl Send for KeySource {}
unsafe impl Sync for KeySource {}

impl KeySource {
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn new(
        version: Version,
        seed: Box<dyn SeedBackend>,
        clock_source: ClockSource,
        validity_length: Duration,
    ) -> Self {
        assert!(
            !validity_length.is_zero(),
            "validity duration must be non-zero"
        );

        let identity = LongTermIdentity::new(version, seed);

        Self {
            clock_source,
            validity_length,
            identity: Arc::new(Mutex::new(identity)),
        }
    }

    pub fn make_online_key(&self) -> OnlineKey {
        self.identity
            .lock()
            .unwrap()
            .make_online_key(&self.clock_source, self.validity_length)
    }

    pub fn public_key(&self) -> PublicKey {
        self.identity.lock().unwrap().public_key()
    }

    #[allow(dead_code)] // it's used by tests
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.identity.lock().unwrap().public_key_bytes()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use roughenough_keys::seed::MemoryBackend;
    use roughenough_protocol::tags::Version;
    use roughenough_protocol::util::ClockSource;

    use crate::keysource::KeySource;

    #[test]
    #[should_panic]
    fn zero_validity_duration_panics() {
        // Given an attempt to create a KeySource
        let version = roughenough_protocol::tags::Version::RfcDraft14;
        let seed: Box<dyn roughenough_keys::seed::SeedBackend> =
            Box::new(MemoryBackend::from_random());
        let clock = ClockSource::System;

        // When the duration is zero
        let zero_duration = Duration::from_secs(0);

        // Then `new` will panic
        let _ = KeySource::new(version, seed, clock, zero_duration);
    }

    #[test]
    fn keysource_key_rotation() {
        // Given: A KeySource with short validity period
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(60); // 1 minute validity

        let backend = Box::new(MemoryBackend::from_random());
        let key_source = KeySource::new(
            Version::RfcDraft14,
            backend,
            clock.clone(),
            validity_duration,
        );

        // Create initial key
        let first_key = key_source.make_online_key();
        let first_pubkey = first_key.public_key_bytes();

        // When: Time advances past key expiration
        clock.set_time(start_time + 61);

        // Then: New key should be different from expired one
        let second_key = key_source.make_online_key();
        let second_pubkey = second_key.public_key_bytes();

        assert_ne!(first_pubkey, second_pubkey);

        // Verify the new key has correct validity period
        let dele = second_key.cert().dele();
        assert_eq!(dele.mint(), start_time + 61);
        assert_eq!(dele.maxt(), start_time + 61 + 60);
    }

    #[test]
    fn worker_key_rotation() {
        // Given: A KeySource with very short validity for testing
        let start_time = 1_000_000u64;
        let clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(2); // 2 second validity

        let backend = Box::new(MemoryBackend::from_random());
        let key_source = Arc::new(KeySource::new(
            Version::RfcDraft14,
            backend,
            clock.clone(),
            validity_duration,
        ));

        let keep_running = Arc::new(AtomicBool::new(true));
        let mut handles = vec![];

        // Spawn multiple threads simulating workers
        for worker_id in 0..3 {
            let key_source_clone = Arc::clone(&key_source);
            let keep_running_clone = Arc::clone(&keep_running);
            let mut clock_clone = clock.clone();

            let handle = thread::spawn(move || {
                let mut keys_used = HashSet::new();
                let mut current_time = start_time;

                while keep_running_clone.load(Ordering::Relaxed) {
                    // Simulate time passing
                    current_time += 1;
                    clock_clone.set_time(current_time);

                    // Get current key
                    let key = key_source_clone.make_online_key();
                    let pubkey = key.public_key_bytes();

                    // Track unique keys used
                    keys_used.insert(pubkey);

                    // Simulate some work
                    thread::sleep(Duration::from_millis(10));

                    // Stop after 5 seconds of simulated time
                    if current_time >= start_time + 5 {
                        break;
                    }
                }

                (worker_id, keys_used)
            });

            handles.push(handle);
        }

        // Let workers run for a bit
        thread::sleep(Duration::from_millis(100));
        keep_running.store(false, Ordering::Relaxed);

        // Collect results
        let mut all_results = vec![];
        for handle in handles {
            let (worker_id, keys_used) = handle.join().expect("Worker thread should not panic");
            println!(
                "Worker {} used {} different keys",
                worker_id,
                keys_used.len()
            );
            all_results.push(keys_used);
        }

        // Then: All workers should have rotated keys at least once
        for keys_used in &all_results {
            assert!(
                keys_used.len() >= 2,
                "Worker should have used at least 2 different keys"
            );
        }
    }

    #[test]
    fn key_validity_at_rotation() {
        // Test that keys remain valid during rotation transitions
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600); // 1 hour
        let rotation_interval = Duration::from_secs(1800); // 30 minutes

        let backend = Box::new(MemoryBackend::from_random());
        let key_source = KeySource::new(
            Version::RfcDraft14,
            backend,
            clock.clone(),
            validity_duration,
        );

        // Get initial key
        let key1 = key_source.make_online_key();

        // Advance to rotation time
        clock.set_time(start_time + rotation_interval.as_secs());
        let key2 = key_source.make_online_key();

        // Verify both keys are valid at rotation boundary
        let key1_valid_until = key1.cert().dele().maxt();
        let key2_valid_from = key2.cert().dele().mint();

        assert!(
            key2_valid_from < key1_valid_until,
            "Keys should have overlapping validity"
        );

        // Calculate overlap period
        let overlap = key1_valid_until - key2_valid_from;
        assert_eq!(overlap, 1800, "Should have 30 minute overlap period");
    }
}
