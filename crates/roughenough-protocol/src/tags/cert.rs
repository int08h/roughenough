use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::{UnexpectedOffsets, UnexpectedTags};
use crate::header::{Header, Header2};
use crate::tag::Tag;
use crate::tags::{Delegation, Signature};
use crate::wire::{FromWire, ToWire};

#[repr(C)]
#[derive(PartialEq, Eq, Clone)]
pub struct Certificate {
    header: Header2,
    signature: Signature,
    delegation: Delegation,
}

impl Default for Certificate {
    fn default() -> Self {
        let mut cert = Self {
            header: Header2::default(),
            signature: Signature::default(),
            delegation: Delegation::default(),
        };

        cert.header.offsets = Self::OFFSETS;
        cert.header.tags = Self::TAGS;
        cert
    }
}

impl Certificate {
    const DELE_OFFSET: u32 = size_of::<Signature>() as u32;
    const OFFSETS: [u32; 1] = [Self::DELE_OFFSET];
    const TAGS: [Tag; 2] = [Tag::SIG, Tag::DELE];

    pub fn new(sig: Signature, dele: Delegation) -> Self {
        Self {
            signature: sig,
            delegation: dele,
            ..Certificate::default()
        }
    }

    pub fn header(&self) -> &impl Header {
        &self.header
    }

    pub fn sig(&self) -> &Signature {
        &self.signature
    }

    pub fn dele(&self) -> &Delegation {
        &self.delegation
    }

    pub fn set_sig(&mut self, sig: Signature) {
        self.signature = sig;
    }

    pub fn set_dele(&mut self, dele: Delegation) {
        self.delegation = dele;
    }
}

impl FromWire for Certificate {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let cert = Certificate {
            header: Header2::from_wire(cursor)?,
            signature: Signature::from_wire(cursor)?,
            delegation: Delegation::from_wire(cursor)?,
        };

        if cert.header.offsets != Self::OFFSETS {
            return Err(UnexpectedOffsets);
        }

        if cert.header.tags != Self::TAGS {
            return Err(UnexpectedTags);
        }

        Ok(cert)
    }
}

impl ToWire for Certificate {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.header.to_wire(cursor)?;
        self.signature.to_wire(cursor)?;
        self.delegation.to_wire(cursor)?;
        Ok(())
    }
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CERT")
            .field("header", &self.header)
            .field("signature", &self.signature)
            .field("delegation", &self.delegation)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn cert_from_wire_fails_on_empty_buffer() {
        let mut data = [];
        let mut cursor = ParseCursor::new(&mut data);
        let result = Certificate::from_wire(&mut cursor);

        assert!(result.is_err());

        match result.unwrap_err() {
            Error::BufferTooSmall(_, _) => { /* ok, expected */ }
            e => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test]
    fn cert_wire_roundtrip() {
        let cert1 = Certificate::default();

        let wire_size = cert1.wire_size();
        assert_eq!(wire_size, size_of::<Certificate>());

        let mut buf = vec![0u8; wire_size];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            cert1.to_wire(&mut cursor).unwrap();
            assert_eq!(cursor.position(), wire_size);
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let cert2 = Certificate::from_wire(&mut cursor).unwrap();

        assert_eq!(cert1, cert2);
        assert_eq!(cursor.remaining(), 0);
    }
}
