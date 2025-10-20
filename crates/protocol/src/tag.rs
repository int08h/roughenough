use std::cmp::Ordering;

use crate::error::Error;
use crate::error::Error::BufferTooSmall;

/// RFC 4.1.3: Tags are used to identify values in Roughtime messages.
///
/// An unsigned 32-bit value (key) that maps to a byte-string (value).
///
/// Tags are ordered by their little-endian encoding of the ASCII tag value.
/// For example, 'SIG\x00' is 0x00474953 and 'NONC' is 0x434e4f4e. Tags are
/// serialized to the wire in big-endian order.
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Tag {
    INVALID = 0x00000000,
    SIG = 0x53494700,
    VER = 0x56455200,
    SRV = 0x53525600,
    NONC = 0x4e4f4e43,
    DELE = 0x44454c45,
    TYPE = 0x54595045,
    PATH = 0x50415448,
    RADI = 0x52414449,
    PUBK = 0x5055424b,
    MIDP = 0x4d494450,
    SREP = 0x53524550,
    VERS = 0x56455253,
    MINT = 0x4d494e54,
    ROOT = 0x524f4f54,
    CERT = 0x43455254,
    MAXT = 0x4d415854,
    INDX = 0x494e4458,
    ZZZZ = 0x5a5a5a5a,
    PAD = 0x504144ff,
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        // RFC 4.2: Tags MUST be listed in the same order as the offsets of their values
        // and be sorted in ascending order by numeric value.
        // Ordering of tags is based on their little-endian value, even though tags are
        // serialized as big-endian. This is confusing, but it is correct.
        let lhs = (*self as u32).to_le_bytes();
        let rhs = (*other as u32).to_le_bytes();
        lhs.cmp(&rhs)
    }
}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Tag {
    pub const HASH_PREFIX_SRV: &'static [u8] = &[0xff];

    /// Returns the on-the-wire representation of this tag.
    pub const fn wire_value(&self) -> [u8; 4] {
        let value = *self as u32;
        value.to_be_bytes()
    }

    /// Return the `Tag` corresponding to the on-the-wire representation in `bytes` or an
    /// `Error::InvalidTag` if `bytes` do not correspond to a valid tag.
    pub const fn from_wire(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(BufferTooSmall(4, bytes.len()));
        }

        match bytes {
            b"SIG\x00" => Ok(Tag::SIG),
            b"VER\x00" => Ok(Tag::VER),
            b"SRV\x00" => Ok(Tag::SRV),
            b"NONC" => Ok(Tag::NONC),
            b"DELE" => Ok(Tag::DELE),
            b"TYPE" => Ok(Tag::TYPE),
            b"PATH" => Ok(Tag::PATH),
            b"RADI" => Ok(Tag::RADI),
            b"PUBK" => Ok(Tag::PUBK),
            b"MIDP" => Ok(Tag::MIDP),
            b"SREP" => Ok(Tag::SREP),
            b"VERS" => Ok(Tag::VERS),
            b"MINT" => Ok(Tag::MINT),
            b"ROOT" => Ok(Tag::ROOT),
            b"CERT" => Ok(Tag::CERT),
            b"MAXT" => Ok(Tag::MAXT),
            b"INDX" => Ok(Tag::INDX),
            b"ZZZZ" => Ok(Tag::ZZZZ),
            b"PAD\xff" => Ok(Tag::PAD),
            _ => {
                let val = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Err(Error::InvalidTag(val))
            }
        }
    }

    /// RFC 4: Messages MAY be recursive, i.e. the value of a tag can itself be a
    /// Roughtime message.
    ///
    /// Returns true if this tag's value is itself an `RtMessage`.
    pub const fn is_nested(&self) -> bool {
        matches!(self, Tag::CERT | Tag::DELE | Tag::SREP)
    }
}

impl TryFrom<u32> for Tag {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::from_wire(value.to_be_bytes().as_ref())
    }
}

impl From<Tag> for u32 {
    fn from(tag: Tag) -> Self {
        u32::from_be_bytes(tag.wire_value())
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::*;

    #[test]
    fn try_from_u32() {
        // invalid conversions
        assert!(Tag::try_from(0_u32).is_err());
        assert!(Tag::try_from(0x12345678_u32).is_err());
        assert!(Tag::try_from(0xFFFFFFFF_u32).is_err());
    }

    #[test]
    fn roundtrip_tag_u32() {
        let tags = [Tag::INDX, Tag::SIG, Tag::TYPE, Tag::PAD, Tag::ZZZZ];
        // Roundtrip conversion succeeds for tags
        for tag in tags {
            let u32_value = u32::from(tag);
            let wire_bytes = tag.wire_value();

            let roundtrip_tag = Tag::try_from(u32_value).unwrap();
            let fromwire_tag = Tag::from_wire(&wire_bytes).unwrap();
            let roundtrip_bytes = roundtrip_tag.wire_value();

            assert_eq!(
                tag, roundtrip_tag,
                "Failed roundtrip conversion for {tag:?}"
            );
            assert_eq!(tag, fromwire_tag, "Failed roundtrip conversion for {tag:?}");
            assert_eq!(
                wire_bytes, roundtrip_bytes,
                "Wire value bytes don't match u32 representation for {tag:?}"
            );
        }
    }

    #[test]
    fn is_nested() {
        assert!(Tag::CERT.is_nested());
        assert!(Tag::DELE.is_nested());
        assert!(Tag::SREP.is_nested());
        assert!(!Tag::VER.is_nested());
    }
}
