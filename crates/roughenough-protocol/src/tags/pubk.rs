use crate::tags::fixed_tag::fixed_tag;

/// RFC 5.2.6: The PUBK tag MUST contain a temporary 32-byte Ed25519 public key.
const SIZE: usize = 32;

fixed_tag! {
    PublicKey, SIZE, "PUBK"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::ParseCursor;
    use crate::error::Error;
    use crate::wire::{FromWire, ToWire};

    #[test]
    fn round_trip() {
        let pubk = PublicKey::from([0x5au8; SIZE]);
        let mut bytes = pubk.as_bytes().unwrap();
        assert_eq!(bytes.len(), SIZE);

        let mut cursor = ParseCursor::new(&mut bytes);
        assert_eq!(PublicKey::from_wire(&mut cursor).unwrap(), pubk);
    }

    #[test]
    fn short_buffer_is_rejected() {
        // PUBK's enclosing DELE checks the declared tag size, so the main
        // failure mode here is a short buffer
        let mut bytes = vec![0u8; SIZE - 1];
        let mut cursor = ParseCursor::new(&mut bytes);
        assert!(PublicKey::from_wire(&mut cursor).is_err());
    }

    #[test]
    fn try_from_slice_checks_length() {
        assert!(matches!(
            PublicKey::try_from(&[0u8; 31][..]),
            Err(Error::WrongTagSize(SIZE, 31))
        ));
        assert!(matches!(
            PublicKey::try_from(&[0u8; 33][..]),
            Err(Error::WrongTagSize(SIZE, 33))
        ));
        assert!(PublicKey::try_from(&[0u8; SIZE][..]).is_ok());
    }
}
