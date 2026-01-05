use std::fmt::Debug;
use std::mem::size_of;
use std::str::FromStr;

use ProtocolVersion::{Google, Invalid, RfcDraft14};

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::InvalidVersion;
use crate::wire::{FromWire, ToWire};

/// A `ProtocolVersion` represents a specific version of the Roughtime protocol. Each version
/// has a unique u32 identifier and SREP and DELE context strings.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolVersion {
    Google = 0x00000000,
    RfcDraft14 = 0x8000000c,
    Invalid = 0xffffffff,
}

impl ProtocolVersion {
    pub fn dele_prefix(&self) -> &'static [u8] {
        match self {
            Google => b"RoughTime v1 delegation signature--\x00",
            RfcDraft14 => b"RoughTime v1 delegation signature\x00",
            Invalid => panic!("invalid version"),
        }
    }

    pub fn srep_prefix(&self) -> &'static [u8] {
        match self {
            Google | RfcDraft14 => b"RoughTime v1 response signature\x00",
            Invalid => panic!("invalid version"),
        }
    }
}

impl ToWire for ProtocolVersion {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        let value = *self as u32;
        cursor.put_u32_le(value);
        Ok(())
    }
}

impl FromWire for ProtocolVersion {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let value = cursor.try_get_u32_le()?;
        match value {
            0x00000000 => Ok(Google),
            0x8000000c => Ok(RfcDraft14),
            _ => Err(InvalidVersion(value)),
        }
    }
}

impl FromStr for ProtocolVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "0" | "google-roughtime" => Ok(Google),
            "1" | "14" | "ietf-roughtime" => Ok(RfcDraft14),
            _ => Err(InvalidVersion(u32::MAX)),
        }
    }
}
