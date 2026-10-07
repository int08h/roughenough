use std::fmt;
use std::fmt::Debug;
use std::mem::size_of;
use std::str::FromStr;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::InvalidVersion;
use crate::wire::{FromWire, ToWire};

/// A `ProtocolVersion` is a u32 version number identifying a specific Roughtime
/// protocol variant.
///
/// Two versions are recognized:
///   * [`Self::RFC`], Roughtime version 1 from RFC 10049, and
///   * [`Self::DRAFT`], 0x8000000c, the version used by servers built to the
///     drafts that preceded the RFC. It lies in the RFC 12.2 experimental
///     range and differs from version 1 only in its signature context strings.
///
/// Every other value, including the rest of the experimental range, is unknown.
/// The server answers only the versions in [`Self::ADVERTISED`]; the client can
/// opt into [`Self::DRAFT`] to reach servers that predate the RFC.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    /// Roughtime version 1 (RFC 10049 12.2)
    pub const RFC: Self = Self(0x00000001);
    /// Pre-RFC draft version 0x8000000c
    pub const DRAFT: Self = Self(0x8000000c);
    /// Internal sentinel for an unset version; never valid on the wire
    pub const INVALID: Self = Self(0xffffffff);

    /// Versions the server negotiates and advertises in VERS, in ascending
    /// wire order (required of VERS tag by RFC 5.2.5).
    pub const ADVERTISED: [ProtocolVersion; 1] = [Self::RFC];

    // RFC 10049 5.2.1 and 5.2.6. Draft 0x8000000c used "RoughTime"; the RFC
    // changed the case for version 1. Both include a terminating zero byte.
    const RFC_SREP_PREFIX: &'static [u8] = b"Roughtime v1 response signature\x00";
    const RFC_DELE_PREFIX: &'static [u8] = b"Roughtime v1 delegation signature\x00";
    const DRAFT_SREP_PREFIX: &'static [u8] = b"RoughTime v1 response signature\x00";
    const DRAFT_DELE_PREFIX: &'static [u8] = b"RoughTime v1 delegation signature\x00";

    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// True when this implementation can parse and verify this version.
    pub const fn is_supported(&self) -> bool {
        self.0 == Self::RFC.0 || self.0 == Self::DRAFT.0
    }

    /// Map a wire value to a protocol version, or `None` if the value is not a
    /// version this implementation supports.
    pub fn from_u32(value: u32) -> Option<Self> {
        let version = Self(value);
        version.is_supported().then_some(version)
    }

    /// Choose the version for a response: the highest advertised version
    /// among those the client offered (RFC 5.2.5: the response version SHOULD
    /// be one supplied by the client). Returns `None` when there is no version
    /// in common; RFC 5.1.1 permits ignoring such requests.
    pub fn negotiate(offered: &[ProtocolVersion]) -> Option<ProtocolVersion> {
        Self::ADVERTISED
            .iter()
            .rev()
            .find(|version| offered.contains(version))
            .copied()
    }

    /// RFC 5.2.6: context string for the long-term key's signature over DELE.
    pub const fn dele_prefix(&self) -> &'static [u8] {
        if self.0 == Self::DRAFT.0 {
            Self::DRAFT_DELE_PREFIX
        } else {
            Self::RFC_DELE_PREFIX
        }
    }

    /// RFC 5.2.1: context string for the online key's signature over SREP.
    pub const fn srep_prefix(&self) -> &'static [u8] {
        if self.0 == Self::DRAFT.0 {
            Self::DRAFT_SREP_PREFIX
        } else {
            Self::RFC_SREP_PREFIX
        }
    }
}

impl Debug for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::RFC => write!(f, "Rfc"),
            Self::DRAFT => write!(f, "Draft"),
            Self::INVALID => write!(f, "Invalid"),
            Self(value) => write!(f, "Unknown(0x{value:08x})"),
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
        Self::from_u32(value).ok_or(InvalidVersion(value))
    }
}

impl FromStr for ProtocolVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "1" | "ietf-roughtime" => Ok(Self::RFC),
            "19" => Ok(Self::DRAFT),
            _ => Err(InvalidVersion(u32::MAX)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(version: ProtocolVersion) {
        let mut buf = vec![0u8; version.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            version.to_wire(&mut cursor).unwrap();
        }
        let mut cursor = ParseCursor::new(&mut buf);
        assert_eq!(ProtocolVersion::from_wire(&mut cursor).unwrap(), version);
    }

    #[test]
    fn google_version_is_not_recognized() {
        // The legacy google-roughtime protocol (0x00000000) is not supported;
        // RFC 12.2 reserves 0x0
        assert_eq!(ProtocolVersion::from_u32(0x00000000), None);

        let mut buf = 0x00000000u32.to_le_bytes().to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        match ProtocolVersion::from_wire(&mut cursor) {
            Err(InvalidVersion(0)) => (), // ok, expected
            other => panic!("expected InvalidVersion(0), got {other:?}"),
        }
    }

    #[test]
    fn version_one_roundtrip() {
        let version = ProtocolVersion::RFC;
        assert_eq!(version.as_u32(), 0x00000001);
        assert_eq!(ProtocolVersion::from_u32(0x00000001), Some(version));
        roundtrip(version);
    }

    #[test]
    fn draft_version_roundtrip() {
        let version = ProtocolVersion::DRAFT;
        assert_eq!(version.as_u32(), 0x8000000c);
        assert_eq!(ProtocolVersion::from_u32(0x8000000c), Some(version));
        roundtrip(version);
    }

    #[test]
    fn other_experimental_versions_are_rejected() {
        // RFC 12.2: 0x80000000-0xbfffffff is reserved for experimental use.
        // Only 0x8000000c is recognized.
        for value in [
            0x80000000u32,
            0x80000001,
            0x8000000b,
            0x8000000d,
            0xbfffffff,
        ] {
            assert_eq!(ProtocolVersion::from_u32(value), None, "0x{value:08x}");
        }
    }

    #[test]
    fn private_use_versions_are_rejected() {
        // RFC 12.2: 0xc0000000-0xffffffff is private use
        for value in [0xc0000000u32, 0xc0000001u32, 0xfffffffeu32] {
            assert!(!ProtocolVersion(value).is_supported(), "0x{value:08x}");
            assert_eq!(ProtocolVersion::from_u32(value), None, "0x{value:08x}");
        }
    }

    #[test]
    fn unknown_versions_are_rejected() {
        for value in [0xffffffffu32, 0x7fffffffu32, 0x00000002u32, 0x00000000u32] {
            assert_eq!(ProtocolVersion::from_u32(value), None, "0x{value:08x}");
        }
        assert!(!ProtocolVersion::INVALID.is_supported());
    }

    #[test]
    fn version_one_context_strings() {
        // RFC 10049 5.2.1 / 5.2.6: context strings include a terminating zero byte
        assert_eq!(
            ProtocolVersion::RFC.srep_prefix(),
            b"Roughtime v1 response signature\x00"
        );
        assert_eq!(
            ProtocolVersion::RFC.dele_prefix(),
            b"Roughtime v1 delegation signature\x00"
        );
    }

    #[test]
    fn draft_context_strings() {
        assert_eq!(
            ProtocolVersion::DRAFT.srep_prefix(),
            b"RoughTime v1 response signature\x00"
        );
        assert_eq!(
            ProtocolVersion::DRAFT.dele_prefix(),
            b"RoughTime v1 delegation signature\x00"
        );
    }

    #[test]
    fn advertised_versions_are_ascending_wire_order() {
        let values: Vec<u32> = ProtocolVersion::ADVERTISED
            .iter()
            .map(|v| v.as_u32())
            .collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        assert_eq!(values, sorted);
    }

    #[test]
    fn server_advertises_only_version_one() {
        assert_eq!(ProtocolVersion::ADVERTISED, [ProtocolVersion::RFC]);
    }

    #[test]
    fn negotiation_selects_only_advertised_versions() {
        const RFC: ProtocolVersion = ProtocolVersion::RFC;
        const DRAFT: ProtocolVersion = ProtocolVersion::DRAFT;

        // RFC 5.2.5: the response version SHOULD be one the client offered
        assert_eq!(ProtocolVersion::negotiate(&[RFC]), Some(RFC));
        assert_eq!(ProtocolVersion::negotiate(&[RFC, DRAFT]), Some(RFC));
        assert_eq!(ProtocolVersion::negotiate(&[DRAFT, RFC]), Some(RFC));

        // The draft version parses but is not negotiated by the server.
        // RFC 5.1.1: with no common version the server MAY ignore the request;
        // this implementation signals that with None
        assert_eq!(ProtocolVersion::negotiate(&[DRAFT]), None);
        assert_eq!(ProtocolVersion::negotiate(&[]), None);
    }

    #[test]
    fn debug_formatting() {
        assert_eq!(format!("{:?}", ProtocolVersion::RFC), "Rfc");
        assert_eq!(format!("{:?}", ProtocolVersion::DRAFT), "Draft");
        assert_eq!(format!("{:?}", ProtocolVersion::INVALID), "Invalid");
        assert_eq!(
            format!("{:?}", ProtocolVersion(0x8000000b)),
            "Unknown(0x8000000b)"
        );
    }

    #[test]
    fn from_str_accepts_version_one() {
        assert_eq!(
            "1".parse::<ProtocolVersion>().unwrap(),
            ProtocolVersion::RFC
        );
        assert_eq!(
            "ietf-roughtime".parse::<ProtocolVersion>().unwrap(),
            ProtocolVersion::RFC
        );
    }

    #[test]
    fn from_str_accepts_draft_name() {
        assert_eq!(
            "19".parse::<ProtocolVersion>().unwrap(),
            ProtocolVersion::DRAFT
        );
        assert!("google-roughtime".parse::<ProtocolVersion>().is_err());
    }
}
