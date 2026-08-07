use crate::tags::fixed_tag::fixed_tag;

/// RFC 5.2.1: A SIG tag value is a 64-byte Ed25519 signature.
const SIZE: usize = 64;

fixed_tag! {
    Signature, SIZE, "SIG"
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::ParseCursor;
    use crate::wire::{FromWire, ToWire};

    #[test]
    fn signature_wire_roundtrip() {
        let mut signature = [0u8; SIZE];
        for (i, item) in signature.iter_mut().enumerate() {
            *item = i as u8;
        }

        let sig = Signature::from(signature);

        // Serialize
        let mut buf = vec![0u8; sig.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            sig.to_wire(&mut cursor).unwrap();
        }

        // Deserialize
        let mut cursor = ParseCursor::new(&mut buf);
        let sig2 = Signature::from_wire(&mut cursor).unwrap();

        // Verify
        assert_eq!(sig, sig2);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn signature_default() {
        let sig = Signature::default();
        assert_eq!(sig.as_ref(), &[0u8; SIZE]);
    }
}
