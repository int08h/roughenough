use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::tags::fixed_tag::FixedTag;
use crate::util::as_hex;
use crate::wire::{FromWire, ToWire};

/// RFC 5.2.6: The PUBK tag MUST contain a temporary 32-byte Ed25519 public key.
const SIZE: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct PublicKey(FixedTag<SIZE>);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PUBK({})", as_hex(self.0.as_slice()))
    }
}

impl ToWire for PublicKey {
    fn wire_size(&self) -> usize {
        SIZE
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.0.to_wire(cursor)
    }
}

impl FromWire for PublicKey {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        Ok(PublicKey(cursor.try_get_fixed()?.into()))
    }
}

impl From<&[u8]> for PublicKey {
    fn from(bytes: &[u8]) -> Self {
        let mut data = [0u8; SIZE];
        data.copy_from_slice(bytes);
        PublicKey(data.into())
    }
}

impl From<[u8; SIZE]> for PublicKey {
    fn from(value: [u8; SIZE]) -> Self {
        Self(value.into())
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
