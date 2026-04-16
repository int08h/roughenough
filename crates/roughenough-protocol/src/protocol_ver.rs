use std::fmt;
use std::fmt::Debug;
use std::mem::size_of;
use std::str::FromStr;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::InvalidVersion;
use crate::wire::{FromWire, ToWire};

/// A `ProtocolVersion` is a u32 version number identifying a specific Roughtime protocol variant.
///
/// RFC draft versions use the private-use range `0x80000000 | draft_number`, so
/// draft-01 is `0x80000001`, draft-12 is `0x8000000c`, etc.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion(pub(crate) u32);

impl ProtocolVersion {
    pub const GOOGLE: Self = Self(0x00000000);
    pub const DRAFT_14: Self = Self(0x8000000c);
    pub const INVALID: Self = Self(0xffffffff);

    const DRAFT_FLAG: u32 = 0x80000000;

    pub fn is_draft(&self) -> bool {
        self.0 & Self::DRAFT_FLAG != 0
    }

    pub fn dele_prefix(&self) -> &'static [u8] {
        match *self {
            Self::GOOGLE => b"RoughTime v1 delegation signature--\x00",
            v if v.is_draft() => b"RoughTime v1 delegation signature\x00",
            _ => panic!("invalid version"),
        }
    }

    pub fn srep_prefix(&self) -> &'static [u8] {
        match *self {
            Self::INVALID => panic!("invalid version"),
            _ => b"RoughTime v1 response signature\x00",
        }
    }
}

impl Debug for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::GOOGLE => write!(f, "Google"),
            Self::INVALID => write!(f, "Invalid"),
            Self(v) if v & Self::DRAFT_FLAG != 0 => {
                write!(f, "Draft(0x{:08x})", v)
            }
            Self(v) => write!(f, "Unknown(0x{:08x})", v),
        }
    }
}

impl ToWire for ProtocolVersion {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        cursor.put_u32_le(self.0);
        Ok(())
    }
}

impl FromWire for ProtocolVersion {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let value = cursor.try_get_u32_le()?;
        match value {
            0x00000000 => Ok(Self::GOOGLE),
            v if v & Self::DRAFT_FLAG != 0 => Ok(Self(v)),
            _ => Err(InvalidVersion(value)),
        }
    }
}

impl FromStr for ProtocolVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "0" | "google-roughtime" => Ok(Self::GOOGLE),
            "1" | "14" | "ietf-roughtime" => Ok(Self::DRAFT_14),
            _ => Err(InvalidVersion(u32::MAX)),
        }
    }
}
