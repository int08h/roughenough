#[cfg(test)]
mod tests {
    // Roughtime requests are fairly simple. There's a limited number of ways to make them invalid.
    // We try anyway. These tests generate pathological requests and ensure they are rejected
    // as expected.
    //
    // Set `SAVE_TO_DISK` to true to save generated requests to disk for debugging or fuzzer
    // input generation.

    use std::io::Write;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;

    use protocol::cursor::ParseCursor;
    use protocol::error::Error;
    use protocol::request::{REQUEST_SIZE, Request};
    use protocol::wire::{FRAME_MAGIC, FromFrame, FromWire};

    // Set to `true` to save bytes to disk for debugging and/or fuzzer corpus generation
    const SAVE_TO_DISK: bool = false;
    static SAVE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[allow(dead_code)]
    fn maybe_save_to_disk(bytes: &[u8]) {
        if SAVE_TO_DISK {
            let fname = format!(
                "adversarial-request-{}.bin",
                SAVE_COUNTER.fetch_add(1, SeqCst)
            );
            let mut file = std::fs::File::create(&fname).unwrap();
            file.write_all(bytes).unwrap();
            println!("Wrote {} bytes to {}", bytes.len(), &fname);
        }
    }

    // Create a request with valid magic but length (u32::MAX) that would cause overflow
    #[test]
    fn overflow_attack_on_frame_length() {
        let mut malicious = vec![0u8; 1024];

        // Valid magic
        malicious[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());

        // Malicious length: u32::MAX would cause buffer allocation issues
        malicious[8..12].copy_from_slice(&u32::MAX.to_le_bytes());

        maybe_save_to_disk(malicious.as_slice());

        let mut cursor = ParseCursor::new(&mut malicious);
        let result = Request::from_frame(&mut cursor);

        // Should fail with UnexpectedFraming error
        match result {
            Err(Error::BufferTooSmall(needed, _found)) => assert_eq!(needed, u32::MAX as usize),
            Err(e) => panic!("Expected UnexpectedFraming error: got {e}"),
            _ => panic!("Expected UnexpectedFraming error"),
        }
    }

    // Request smaller than minimum possible size.
    #[test]
    fn undersized_buffer_attack() {
        let mut tiny = vec![0u8; 15]; // Less than header size

        // Valid magic
        tiny[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());

        let mut cursor = ParseCursor::new(&mut tiny);
        let result = Request::from_frame(&mut cursor);

        maybe_save_to_disk(tiny.as_slice());

        // Should be rejected
        assert!(result.is_err());
        match result {
            Err(Error::UnexpectedFraming(found)) => assert_eq!(found, 0),
            _ => panic!(
                "Expected UnexpectedFraming(0) error: got {:?}",
                result.unwrap_err()
            ),
        }
    }

    // The Request frame length value is 1 byte too large
    #[test]
    fn one_byte_oversized_request_rejection() {
        let mut oversized = vec![0u8; REQUEST_SIZE];

        // Valid magic and length
        oversized[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        // One byte too many: 1012 + 1
        oversized[8..12].copy_from_slice(&1013u32.to_le_bytes());

        maybe_save_to_disk(oversized.as_slice());

        let mut cursor = ParseCursor::new(&mut oversized);
        let result = Request::from_frame(&mut cursor);

        match result {
            Err(Error::BufferTooSmall(needed, _found)) => assert_eq!(needed, 1013),
            Err(e) => panic!("Expected UnexpectedFraming error: got {e}"),
            _ => panic!("Expected UnexpectedFraming error for oversized request"),
        }
    }

    // Create Request with tag count (u32::MAX) that would overflow offset calculations
    #[test]
    fn tag_count_overflow() {
        let mut malicious = vec![0u8; REQUEST_SIZE];

        // Valid frame
        malicious[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        malicious[8..12].copy_from_slice(&1012u32.to_le_bytes());

        // Malicious tag count that is an overflow when calculating offsets
        let overflow_tags = u32::MAX;
        malicious[12..16].copy_from_slice(&overflow_tags.to_le_bytes());

        maybe_save_to_disk(malicious.as_slice());

        let mut cursor = ParseCursor::new(&mut malicious);
        let result = Request::from_frame(&mut cursor);

        // Should fail with MismatchedNumTags
        assert!(matches!(result, Err(Error::MismatchedNumTags(_, _))));
    }

    // Create request with valid tag count but offsets pointing outside request length
    #[test]
    fn offset_out_of_bounds() {
        let mut malicious = vec![0u8; REQUEST_SIZE];

        // Valid frame
        malicious[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        malicious[8..12].copy_from_slice(&1012u32.to_le_bytes());

        // Valid tag count (4)
        malicious[12..16].copy_from_slice(&4u32.to_le_bytes());

        // Malicious offset pointing beyond buffer
        let bad_offset = (REQUEST_SIZE + 100) as u32;
        malicious[16..20].copy_from_slice(&bad_offset.to_le_bytes());

        maybe_save_to_disk(malicious.as_slice());

        let mut cursor = ParseCursor::new(&mut malicious);
        let result = Request::from_wire(&mut cursor);

        // Should fail when trying to parse tags with bad offsets
        assert!(result.is_err());
    }

    // Test that common corruption is rejected efficiently
    #[test]
    fn validation_performance_dos() {
        let mut bad_packets = Vec::new();

        // Wrong magic
        let mut wrong_magic = vec![0u8; REQUEST_SIZE];
        wrong_magic[0..8].copy_from_slice(&0xDEADBEEFu64.to_be_bytes());
        bad_packets.push(wrong_magic);

        // Wrong frame length
        let mut wrong_len = vec![0u8; REQUEST_SIZE];
        wrong_len[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        wrong_len[8..12].copy_from_slice(&999u32.to_le_bytes());
        bad_packets.push(wrong_len);

        // Wrong tag count
        let mut wrong_tags = vec![0u8; REQUEST_SIZE];
        wrong_tags[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        wrong_tags[8..12].copy_from_slice(&1012u32.to_le_bytes());
        wrong_tags[12..16].copy_from_slice(&10u32.to_le_bytes()); // Not 4 or 5
        bad_packets.push(wrong_tags);

        // All should fail early validation
        for packet in &mut bad_packets {
            maybe_save_to_disk(packet.as_slice());
            let mut cursor = ParseCursor::new(packet);
            assert!(Request::from_wire(&mut cursor).is_err());
        }
    }

    #[test]
    fn tag_value_size_mismatch() {
        // Test tags claiming sizes that don't match their actual type
        let mut malicious = vec![0u8; REQUEST_SIZE];

        // Valid frame
        malicious[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        malicious[8..12].copy_from_slice(&1012u32.to_le_bytes());

        // 4 tags but with mismatched sizes
        malicious[12..16].copy_from_slice(&4u32.to_le_bytes());

        // Make first offset point to a location with insufficient space
        malicious[16..20].copy_from_slice(&((REQUEST_SIZE - 2) as u32).to_le_bytes());

        maybe_save_to_disk(malicious.as_slice());

        let mut cursor = ParseCursor::new(&mut malicious);
        let result = Request::from_wire(&mut cursor);

        // Should fail when trying to read tag values
        assert!(result.is_err());
    }

    // Frame's length field is zero
    #[test]
    fn zero_length_frame() {
        let mut malicious = vec![0u8; 1024];

        // Valid magic but zero length
        malicious[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        malicious[8..12].copy_from_slice(&0u32.to_le_bytes());

        maybe_save_to_disk(malicious.as_slice());

        let mut cursor = ParseCursor::new(&mut malicious);
        let result = Request::from_frame(&mut cursor);

        match result {
            Err(Error::UnexpectedFraming(found)) => assert_eq!(found, 0),
            Err(e) => panic!("Expected UnexpectedFraming(0) error: got {e}"),
            _ => panic!("Expected UnexpectedFraming(0) error"),
        }
    }

    #[test]
    fn recursive_tag_references() {
        // While Roughtime doesn't have nested structures, test that
        // offset calculations can't create infinite loops
        let mut malicious = vec![0u8; REQUEST_SIZE];

        // Valid frame
        malicious[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        malicious[8..12].copy_from_slice(&1012u32.to_le_bytes());

        // 4 tags
        malicious[12..16].copy_from_slice(&4u32.to_le_bytes());

        // Create circular offset references (though protocol doesn't support this)
        // This tests robustness of offset validation
        malicious[16..20].copy_from_slice(&20u32.to_le_bytes()); // Points to itself
        malicious[20..24].copy_from_slice(&16u32.to_le_bytes()); // Points back

        maybe_save_to_disk(malicious.as_slice());

        let mut cursor = ParseCursor::new(&mut malicious);
        let result = Request::from_wire(&mut cursor);

        // Should fail with unexpected offsets
        assert!(result.is_err());
    }

    #[test]
    fn negative_offset_underflow() {
        // Test offset calculations that could underflow
        let mut malicious = vec![0u8; REQUEST_SIZE];

        // Valid frame
        malicious[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        malicious[8..12].copy_from_slice(&1012u32.to_le_bytes());

        // 4 tags
        malicious[12..16].copy_from_slice(&4u32.to_le_bytes());

        // First offset less than header size (would underflow)
        malicious[16..20].copy_from_slice(&5u32.to_le_bytes());

        maybe_save_to_disk(malicious.as_slice());

        let mut cursor = ParseCursor::new(&mut malicious);
        let result = Request::from_wire(&mut cursor);

        // Should fail due to invalid offsets
        assert!(result.is_err());
    }

    #[test]
    fn non_monotonic_offsets() {
        // Offsets should be monotonically increasing
        let mut malicious = vec![0u8; REQUEST_SIZE];

        // Valid frame
        malicious[0..8].copy_from_slice(&FRAME_MAGIC.to_be_bytes());
        malicious[8..12].copy_from_slice(&1012u32.to_le_bytes());

        // 4 tags
        malicious[12..16].copy_from_slice(&4u32.to_le_bytes());

        // Non-monotonic offsets
        malicious[16..20].copy_from_slice(&100u32.to_le_bytes());
        malicious[20..24].copy_from_slice(&50u32.to_le_bytes()); // Goes backwards

        maybe_save_to_disk(malicious.as_slice());

        let mut cursor = ParseCursor::new(&mut malicious);
        let result = Request::from_wire(&mut cursor);

        // Should fail validation
        assert!(result.is_err());
    }
}
