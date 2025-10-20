use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::tags::fixed_tag::FixedTag;
use crate::util::as_hex;
use crate::wire::{FromWire, ToWire};

/// RFC 5.2.1: A SIG tag value is a 64-byte Ed25519 signature.
const SIZE: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct Signature(FixedTag<SIZE>);

impl Default for Signature {
    fn default() -> Self {
        Self(FixedTag::new([0u8; SIZE]))
    }
}

impl FromWire for Signature {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        Ok(Self(cursor.try_get_fixed()?.into()))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SIG({})", as_hex(self.0.as_slice()))
    }
}

impl ToWire for Signature {
    fn wire_size(&self) -> usize {
        SIZE
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.0.to_wire(cursor)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<[u8; SIZE]> for Signature {
    fn from(signature: [u8; SIZE]) -> Self {
        Self(signature.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
