use crate::tags::fixed_tag::fixed_tag;

/// RFC 5.1.2: The value of the NONC tag is a 32-byte nonce.
const SIZE: usize = 32;

fixed_tag! {
    /// A random "number used once" (nonce) used to ensure that requests are unique.
    Nonce, SIZE, "NONC"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::ParseCursor;
    use crate::error::Error;
    use crate::wire::{FromWire, FromWireN, ToWire};

    #[test]
    fn round_trip() {
        let nonce = Nonce::from([0x42u8; SIZE]);
        let mut bytes = nonce.as_bytes().unwrap();
        assert_eq!(bytes.len(), SIZE);

        let mut cursor = ParseCursor::new(&mut bytes);
        assert_eq!(Nonce::from_wire(&mut cursor).unwrap(), nonce);
    }

    #[test]
    fn wrong_length_is_rejected() {
        let mut bytes = vec![0u8; 64];
        for bad_len in [0usize, 31, 33, 64] {
            let mut cursor = ParseCursor::new(&mut bytes);
            assert!(matches!(
                Nonce::from_wire_n(&mut cursor, bad_len),
                Err(Error::WrongTagSize(SIZE, n)) if n == bad_len
            ));
        }
    }

    #[test]
    fn short_buffer_is_rejected() {
        let mut bytes = vec![0u8; SIZE - 1];
        let mut cursor = ParseCursor::new(&mut bytes);
        assert!(Nonce::from_wire(&mut cursor).is_err());
    }

    #[test]
    fn debug_label() {
        let nonce = Nonce::from([0xabu8; SIZE]);
        assert!(format!("{nonce:?}").starts_with("NONC(abab"));
    }

    #[test]
    fn try_from_slice_checks_length() {
        assert!(matches!(
            Nonce::try_from(&[0u8; 31][..]),
            Err(Error::WrongTagSize(SIZE, 31))
        ));
        assert!(matches!(
            Nonce::try_from(&[0u8; 33][..]),
            Err(Error::WrongTagSize(SIZE, 33))
        ));
        assert!(Nonce::try_from(&[0u8; SIZE][..]).is_ok());
    }
}
