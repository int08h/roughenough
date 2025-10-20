#[cfg(test)]
mod tests {
    use std::time::Duration;

    use protocol::tags::Version;
    use protocol::util::ClockSource;

    use crate::longterm::LongTermIdentity;
    use crate::online::OnlineKey;
    use crate::seed::MemoryBackend;

    // Helper function to check if a key is expired based on current time
    fn is_key_expired(key: &OnlineKey, clock: &ClockSource) -> bool {
        let now = clock.epoch_seconds();
        let maxt = key.cert().dele().maxt();
        now >= maxt
    }

    // Helper function to verify key validity window
    fn verify_validity_window(key: &OnlineKey, expected_mint: u64, expected_duration: u64) {
        let dele = key.cert().dele();
        assert_eq!(dele.mint(), expected_mint);
        assert_eq!(dele.maxt(), expected_mint + expected_duration);
    }

    #[test]
    fn online_key_has_correct_validity_period() {
        // Given: A mock clock at a specific time and a validity duration
        let start_time = 1_000_000u64;
        let clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600); // 1 hour

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(Version::RfcDraft14, backend);

        // When: An online key is created
        let online_key = identity.make_online_key(&clock, validity_duration);

        // Then: The DELE certificate has MINT = now and MAXT = now + validity
        verify_validity_window(&online_key, start_time, validity_duration.as_secs());
    }

    #[test]
    fn detect_expired_online_key() {
        // Given: An online key with 1 hour validity
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(Version::RfcDraft14, backend);
        let online_key = identity.make_online_key(&clock, validity_duration);

        // Initially, key should not be expired
        assert!(!is_key_expired(&online_key, &clock));

        // When: Time advances to just before expiration
        clock.set_time(start_time + 3599);
        assert!(!is_key_expired(&online_key, &clock));

        // When: Time advances beyond MAXT
        clock.set_time(start_time + 3600);

        // Then: Key should be identified as expired
        assert!(is_key_expired(&online_key, &clock));

        // Further advance should still show expired
        clock.set_time(start_time + 7200);
        assert!(is_key_expired(&online_key, &clock));
    }

    #[test]
    fn multiple_key_rotations_over_time() {
        // Given: Short validity periods for testing
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(100);
        let rotation_interval = 50u64; // Rotate every 50 seconds

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(Version::RfcDraft14, backend);

        let mut keys = Vec::new();
        let mut current_time = start_time;

        // When: Time advances through multiple rotation cycles
        for i in 0..5 {
            let key = identity.make_online_key(&clock, validity_duration);
            verify_validity_window(&key, current_time, validity_duration.as_secs());
            keys.push(key);

            if i < 4 {
                current_time += rotation_interval;
                clock.set_time(current_time);
            }
        }

        // Then: Each rotation produces a new key with correct validity windows
        assert_eq!(keys.len(), 5);

        // All keys should have different public keys
        let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key_bytes()).collect();
        for i in 0..pubkeys.len() {
            for j in (i + 1)..pubkeys.len() {
                assert_ne!(pubkeys[i], pubkeys[j]);
            }
        }

        // Check validity windows don't have gaps
        for i in 0..keys.len() - 1 {
            let current_maxt = keys[i].cert().dele().maxt();
            let next_mint = keys[i + 1].cert().dele().mint();
            // Next key starts before current expires (overlap)
            assert!(next_mint < current_maxt);
        }
    }

    #[test]
    fn handle_request_at_validity_boundary() {
        // Given: A key about to expire (1 second before maxt)
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(Version::RfcDraft14, backend);
        let mut online_key = identity.make_online_key(&clock, validity_duration);

        // Advance to 1 second before expiration
        clock.set_time(start_time + 3599);

        // When: A request is processed (simulate by creating SREP)
        let merkle_root = protocol::tags::MerkleRoot::from([0x42; 32]);
        let (srep, sig) = online_key.make_srep(&merkle_root);

        // Then: Response should still be signed successfully
        assert_eq!(srep.root(), &merkle_root);
        assert_eq!(srep.midp(), start_time + 3599);
        assert_ne!(sig.as_ref(), vec![0u8; 64]);
    }

    #[test]
    fn ensure_key_validity_overlap() {
        // Given: 1 hour validity and 30 minute rotation
        let start_time = 1_000_000u64;
        let mut clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600); // 1 hour validity
        let rotation_interval = 1800u64; // 30 minute rotation

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(Version::RfcDraft14, backend);

        // Create first key
        let first_key = identity.make_online_key(&clock, validity_duration);

        // When: Key rotation occurs
        clock.set_time(start_time + rotation_interval);
        let second_key = identity.make_online_key(&clock, validity_duration);

        // Then: Old and new keys have overlapping validity periods
        let first_maxt = first_key.cert().dele().maxt();
        let second_mint = second_key.cert().dele().mint();

        // Second key starts before first expires
        assert!(second_mint < first_maxt);

        // Overlap period calculation
        let overlap_start = second_mint;
        let overlap_end = first_maxt;
        let overlap_duration = overlap_end - overlap_start;

        // Should have 30 minutes of overlap
        assert_eq!(overlap_duration, 1800);

        // During overlap, both keys are valid
        clock.set_time(start_time + rotation_interval + 900); // 15 min after rotation
        assert!(!is_key_expired(&first_key, &clock));
        assert!(!is_key_expired(&second_key, &clock));
    }

    #[test]
    fn key_properties_remain_consistent() {
        // Test that key properties (version, clock source) are properly set
        let start_time = 1_000_000u64;
        let clock = ClockSource::new_mock(start_time);
        let validity_duration = Duration::from_secs(3600);

        let backend = Box::new(MemoryBackend::from_random());
        let mut identity = LongTermIdentity::new(Version::RfcDraft14, backend);
        let mut online_key = identity.make_online_key(&clock, validity_duration);

        // Create SREP and verify it has correct properties
        let merkle_root = protocol::tags::MerkleRoot::from([0x77; 32]);
        let (srep, _) = online_key.make_srep(&merkle_root);

        assert_eq!(srep.midp(), start_time);
        assert_eq!(*srep.ver(), Version::RfcDraft14);
        assert_eq!(srep.root(), &merkle_root);
    }
}
