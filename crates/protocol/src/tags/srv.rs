use std::fmt::Debug;
use std::mem::size_of;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::BufferTooSmall;
use crate::util::as_hex;
use crate::wire::{FromWire, ToWire};

/// The SRV tag is used by the client to indicate which long-term public key it expects to
/// verify the response with.
///
/// The value of the SRV tag is H(0xff || public_key) where public_key is the server's long-term,
/// 32-byte Ed25519 public key and H is the first 32-bytes of SHA-512.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SrvCommitment([u8; 32]);

impl SrvCommitment {
    pub const HASH_PREFIX_SRV: &'static [u8] = &[0xff];
}

impl Debug for SrvCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SRV({})", as_hex(&self.0))
    }
}

impl ToWire for SrvCommitment {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if cursor.remaining() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.remaining()));
        }

        cursor.put_slice(&self.0);
        Ok(())
    }
}

impl FromWire for SrvCommitment {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let mut srv = SrvCommitment::default();
        cursor.try_copy_to_slice(&mut srv.0)?;
        Ok(srv)
    }
}

impl From<[u8; 32]> for SrvCommitment {
    fn from(bytes: [u8; 32]) -> Self {
        SrvCommitment(bytes)
    }
}

impl TryFrom<&[u8]> for SrvCommitment {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(BufferTooSmall(32, value.len()));
        }
        let buf: [u8; 32] = value.try_into().unwrap();
        Ok(SrvCommitment(buf))
    }
}

impl AsRef<[u8]> for SrvCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
