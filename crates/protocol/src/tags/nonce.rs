use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::tags::fixed_tag::FixedTag;
use crate::util::as_hex;
use crate::wire::{FromWire, ToWire};

/// RFC 5.1.2: The value of the NONC tag is a 32-byte nonce.
const SIZE: usize = 32;

/// A random "number used once" (nonce) used to ensure that requests are unique.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Nonce(FixedTag<SIZE>);

impl Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NONC({})", as_hex(self.0.as_slice()))
    }
}

impl ToWire for Nonce {
    fn wire_size(&self) -> usize {
        SIZE
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.0.to_wire(cursor)
    }
}

impl FromWire for Nonce {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        Ok(Nonce(cursor.try_get_fixed()?.into()))
    }
}

impl From<[u8; 32]> for Nonce {
    fn from(bytes: [u8; SIZE]) -> Self {
        Nonce(bytes.into())
    }
}

impl From<&[u8]> for Nonce {
    fn from(bytes: &[u8]) -> Self {
        let mut data = [0u8; SIZE];
        data.copy_from_slice(bytes);
        Nonce(data.into())
    }
}

impl From<&Vec<u8>> for Nonce {
    fn from(bytes: &Vec<u8>) -> Self {
        Nonce::from(bytes.as_slice())
    }
}

impl From<Nonce> for [u8; SIZE] {
    fn from(nonce: Nonce) -> Self {
        *nonce.0.as_bytes()
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
