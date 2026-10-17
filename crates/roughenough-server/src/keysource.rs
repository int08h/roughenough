use std::sync::{Arc, Mutex};
use std::time::Duration;

use roughenough_common::clocksource::ClockSource;
use roughenough_keys::longterm::LongTermIdentity;
use roughenough_keys::online::OnlineKey;
use roughenough_keys::seed::SeedBackend;
use roughenough_protocol::tags::PublicKey;

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

impl KeySource {
    pub fn new(
        seed: Box<dyn SeedBackend>,
        clock_source: ClockSource,
        validity_length: Duration,
    ) -> Self {
        assert!(
            !validity_length.is_zero(),
            "validity duration must be non-zero"
        );

        let identity = LongTermIdentity::new(seed);

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

    pub fn clock(&self) -> &ClockSource {
        &self.clock_source
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
    use std::time::Duration;

    use roughenough_common::clocksource::ClockSource;
    use roughenough_keys::seed::MemoryBackend;

    use crate::keysource::KeySource;

    fn assert_send_sync<T: Send + Sync>() {}

    // Compile-time proof of the thread-safety the deleted `unsafe impl
    // Send/Sync for KeySource` used to assert by hand; holds because
    // `SeedBackend: Send` is now a supertrait bound
    #[test]
    fn keysource_is_send_sync() {
        assert_send_sync::<KeySource>();
    }

    #[test]
    #[should_panic]
    fn zero_validity_duration_panics() {
        // Given an attempt to create a KeySource
        let seed: Box<dyn roughenough_keys::seed::SeedBackend> =
            Box::new(MemoryBackend::from_random());
        let clock = ClockSource::System;

        // When the duration is zero
        let zero_duration = Duration::from_secs(0);

        // Then `new` will panic
        let _ = KeySource::new(seed, clock, zero_duration);
    }

    #[test]
    fn keysource_key_rotation() {
        // Given: A KeySource with short validity period
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(60); // 1 minute validity

        let backend = Box::new(MemoryBackend::from_random());
        let key_source = KeySource::new(backend, clock.clone(), validity_duration);

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
}
