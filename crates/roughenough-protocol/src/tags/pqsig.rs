//! Experimental Falcon-512-padded signature tag

use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::tags::fixed_tag::FixedTag;
use crate::util::as_hex;
use crate::wire::{FromWire, ToWire};

const SIZE: usize = 666;

#[derive(Clone, PartialEq, Eq)]
pub struct PQSignature(FixedTag<SIZE>);

impl PQSignature {
    pub fn new(data: [u8; SIZE]) -> Self {
        PQSignature(FixedTag::new(data))
    }
}

impl Default for PQSignature {
    fn default() -> Self {
        Self(FixedTag::new([0u8; SIZE]))
    }
}

impl FromWire for PQSignature {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        Ok(Self(cursor.try_get_fixed()?.into()))
    }
}

impl Debug for PQSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SIGQ({})", as_hex(self.0.as_slice()))
    }
}

impl ToWire for PQSignature {
    fn wire_size(&self) -> usize {
        SIZE
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.0.to_wire(cursor)
    }
}

impl AsRef<[u8]> for PQSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<[u8; SIZE]> for PQSignature {
    fn from(signature: [u8; SIZE]) -> Self {
        Self(signature.into())
    }
}
