use crate::tags::fixed_tag::fixed_tag;

/// RFC 5.2.5: The ROOT tag MUST contain a 32-byte value of a Merkle tree root.
const SIZE: usize = 32;

fixed_tag! {
    MerkleRoot, SIZE, "ROOT"
}

impl AsRef<[u8; SIZE]> for MerkleRoot {
    fn as_ref(&self) -> &[u8; SIZE] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::ParseCursor;
    use crate::error::Error;
    use crate::wire::{FromWire, ToWire};

    #[test]
    fn wire_roundtrip() {
        let root1 = MerkleRoot::from([0x42; SIZE]);
        let wire_size = root1.wire_size();
        let mut buf = vec![0u8; wire_size];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            root1.to_wire(&mut cursor).unwrap();
            assert_eq!(cursor.position(), wire_size);
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let root2 = MerkleRoot::from_wire(&mut cursor).unwrap();

        assert_eq!(root1, root2);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn from_wire_fails_on_empty_buffer() {
        let mut data = [];
        let mut cursor = ParseCursor::new(&mut data);
        let result = MerkleRoot::from_wire(&mut cursor);

        assert!(
            result.is_err(),
            "deserialization should fail on empty buffer"
        );

        match result.unwrap_err() {
            Error::BufferTooSmall(_, _) => {}
            e => panic!("Unexpected error: {e:?}"),
        }
    }
}
