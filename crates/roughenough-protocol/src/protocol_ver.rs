use std::fmt::Debug;
use std::mem::size_of;
use std::str::FromStr;

use ProtocolVersion::{Invalid, Rfc, RfcDraft19};

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::InvalidVersion;
use crate::wire::{FromWire, ToWire};

/// A `ProtocolVersion` represents a specific version of the Roughtime protocol. Each version
/// has a unique u32 identifier and SREP and DELE context strings.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolVersion {
    /// Roughtime version 1, the version (soon to be) assigned by the published RFC
    Rfc = 0x00000001,
    /// The test version number assigned by draft 19 of the RFC
    RfcDraft19 = 0x8000000c,
    Invalid = 0xffffffff,
}

impl ProtocolVersion {
    /// All versions this implementation supports, in ascending wire order
    /// (the order required of the VERS tag by RFC 5.2.5)
    pub const SUPPORTED: [ProtocolVersion; 2] = [Rfc, RfcDraft19];

    /// Map a wire value to a known protocol version, or `None` if the value is
    /// not a version this implementation supports.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x00000001 => Some(Rfc),
            0x8000000c => Some(RfcDraft19),
            _ => None,
        }
    }

    /// Choose the version for a response: the highest-preference supported
    /// version among those the client offered (RFC 5.2.5: the response version
    /// SHOULD be one supplied by the client). Returns `None` when there is no
    /// version in common; RFC 5.1.1 permits ignoring such requests.
    pub fn negotiate(offered: &[ProtocolVersion]) -> Option<ProtocolVersion> {
        offered
            .iter()
            .filter(|version| Self::SUPPORTED.contains(version))
            .max_by_key(|version| version.preference())
            .copied()
    }

    /// Rank for version negotiation: a higher value is preferred. Preference is
    /// by protocol recency, NOT numeric wire value -- version 1 (0x00000001)
    /// outranks the draft test version (0x8000000c).
    pub fn preference(&self) -> u8 {
        match self {
            Rfc => 2,
            RfcDraft19 => 1,
            Invalid => 0,
        }
    }

    pub fn dele_prefix(&self) -> &'static [u8] {
        match self {
            Rfc | RfcDraft19 => b"RoughTime v1 delegation signature\x00",
            Invalid => panic!("invalid version"),
        }
    }

    pub fn srep_prefix(&self) -> &'static [u8] {
        match self {
            Rfc | RfcDraft19 => b"RoughTime v1 response signature\x00",
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
        Self::from_u32(value).ok_or(InvalidVersion(value))
    }
}

impl FromStr for ProtocolVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "1" => Ok(Rfc),
            "19" | "ietf-roughtime" => Ok(RfcDraft19),
            _ => Err(InvalidVersion(u32::MAX)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_version_is_not_recognized() {
        // The legacy google-roughtime protocol (0x00000000) is not supported
        assert_eq!(ProtocolVersion::from_u32(0x00000000), None);

        let mut buf = 0x00000000u32.to_le_bytes().to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        match ProtocolVersion::from_wire(&mut cursor) {
            Err(InvalidVersion(0)) => (), // ok, expected
            other => panic!("expected InvalidVersion(0), got {other:?}"),
        }
    }

    #[test]
    fn draft19_version_roundtrip() {
        let version = RfcDraft19;
        assert_eq!(version as u32, 0x8000000c);
        assert_eq!(ProtocolVersion::from_u32(0x8000000c), Some(version));

        let mut buf = vec![0u8; version.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            version.to_wire(&mut cursor).unwrap();
        }
        let mut cursor = ParseCursor::new(&mut buf);
        assert_eq!(ProtocolVersion::from_wire(&mut cursor).unwrap(), version);
    }

    #[test]
    fn version_one_roundtrip() {
        let version = Rfc;
        assert_eq!(version as u32, 0x00000001);
        assert_eq!(ProtocolVersion::from_u32(0x00000001), Some(version));

        let mut buf = vec![0u8; version.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            version.to_wire(&mut cursor).unwrap();
        }
        let mut cursor = ParseCursor::new(&mut buf);
        assert_eq!(ProtocolVersion::from_wire(&mut cursor).unwrap(), version);
    }

    #[test]
    fn version_one_context_strings() {
        // RFC 5.2.1 / 5.2.6: context strings include a terminating zero byte
        assert_eq!(Rfc.srep_prefix(), b"RoughTime v1 response signature\x00");
        assert_eq!(Rfc.dele_prefix(), b"RoughTime v1 delegation signature\x00");
    }

    #[test]
    fn preference_is_by_recency_not_wire_value() {
        // 0x00000001 outranks 0x8000000c despite the smaller wire value
        assert!(
            Rfc.preference() > RfcDraft19.preference(),
            "RFC version 1 must be preferred over the draft version"
        );
    }

    #[test]
    fn supported_versions_are_ascending_wire_order() {
        let values: Vec<u32> = ProtocolVersion::SUPPORTED
            .iter()
            .map(|v| *v as u32)
            .collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        assert_eq!(values, sorted);
    }

    #[test]
    fn negotiation_picks_highest_preference() {
        use ProtocolVersion::{Rfc, RfcDraft19};

        // RFC 5.2.5: the response version SHOULD be one the client offered.
        // Preference is by recency: version 1 outranks the draft version.
        assert_eq!(ProtocolVersion::negotiate(&[Rfc]), Some(Rfc));
        assert_eq!(ProtocolVersion::negotiate(&[RfcDraft19]), Some(RfcDraft19));
        assert_eq!(ProtocolVersion::negotiate(&[Rfc, RfcDraft19]), Some(Rfc));
        assert_eq!(ProtocolVersion::negotiate(&[RfcDraft19, Rfc]), Some(Rfc));

        // RFC 5.1.1: with no common version the server MAY ignore the request;
        // this implementation signals that with None
        assert_eq!(ProtocolVersion::negotiate(&[]), None);
    }

    #[test]
    fn from_str_accepts_version_one() {
        assert_eq!("1".parse::<ProtocolVersion>().unwrap(), Rfc);
    }

    #[test]
    fn from_str_accepts_draft19_names() {
        assert_eq!("19".parse::<ProtocolVersion>().unwrap(), RfcDraft19);
        assert_eq!(
            "ietf-roughtime".parse::<ProtocolVersion>().unwrap(),
            RfcDraft19
        );
        assert!("google-roughtime".parse::<ProtocolVersion>().is_err());
    }
}
