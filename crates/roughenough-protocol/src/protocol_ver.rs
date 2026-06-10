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
/// RFC draft revisions use private-use version numbers with the high bit set
/// (`0x80000000 | draft identifier`). This implementation accepts *any*
/// draft-flagged version and handles them all uniformly.
///
/// All draft versions are answered the same way on the assumption that no pre-8
/// clients remain.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    /// Roughtime version 1, the version (soon to be) assigned by the published RFC
    pub const RFC: Self = Self(0x00000001);
    /// The draft test version this implementation offers (client) and
    /// advertises in VERS (server): 0x8000000c. Acceptance is broader, see [`Self::is_draft`].
    pub const DRAFT: Self = Self(0x8000000c);
    /// Internal sentinel for an unset version; never valid on the wire
    pub const INVALID: Self = Self(0xffffffff);

    const DRAFT_FLAG: u32 = 0x8000_0000;

    /// Versions advertised in VERS and offered by the client, in ascending
    /// wire order (required of VERS tag by RFC 5.2.5). The server
    /// *accepts* more than these: see [`Self::is_supported`].
    pub const ADVERTISED: [ProtocolVersion; 2] = [Self::RFC, Self::DRAFT];

    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// True when this is a draft-flagged version number.
    pub const fn is_draft(&self) -> bool {
        self.0 & Self::DRAFT_FLAG != 0 && self.0 != Self::INVALID.0
    }

    /// True when this implementation can respond using this version: RFC version 1
    /// or any draft revision.
    pub const fn is_supported(&self) -> bool {
        self.0 == Self::RFC.0 || self.is_draft()
    }

    /// Map a wire value to a protocol version, or `None` if the value is not a
    /// version this implementation supports.
    pub fn from_u32(value: u32) -> Option<Self> {
        let version = Self(value);
        version.is_supported().then_some(version)
    }

    /// Choose the version for a response: the highest-preference supported
    /// version among those the client offered (RFC 5.2.5: the response version
    /// SHOULD be one supplied by the client). Returns `None` when there is no
    /// version in common; RFC 5.1.1 permits ignoring such requests.
    pub fn negotiate(offered: &[ProtocolVersion]) -> Option<ProtocolVersion> {
        offered
            .iter()
            .filter(|version| version.is_supported())
            .max_by_key(|version| version.preference())
            .copied()
    }

    /// Rank for version negotiation: a higher value is preferred. RFC version 1
    /// outranks every draft despite its smaller wire value; among drafts the
    /// highest wire value (the most recent draft) wins.
    pub fn preference(&self) -> u64 {
        if *self == Self::RFC {
            1 << 32
        } else if self.is_draft() {
            u64::from(self.0 & !Self::DRAFT_FLAG) + 1
        } else {
            0
        }
    }

    pub fn dele_prefix(&self) -> &'static [u8] {
        if self.is_supported() {
            b"RoughTime v1 delegation signature\x00"
        } else {
            panic!("invalid version")
        }
    }

    pub fn srep_prefix(&self) -> &'static [u8] {
        if self.is_supported() {
            b"RoughTime v1 response signature\x00"
        } else {
            panic!("invalid version")
        }
    }
}

impl Debug for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::RFC => write!(f, "Rfc"),
            Self::INVALID => write!(f, "Invalid"),
            Self(value) if self.is_draft() => write!(f, "Draft(0x{value:08x})"),
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
            // "19" is historical: it names the draft that assigned 0x8000000c.
            // If DRAFT is ever bumped to a different wire value, re-pin "19"
            // to the literal 0x8000000c or retire it.
            "19" => Ok(Self::DRAFT),
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
    fn draft_version_roundtrip() {
        let version = ProtocolVersion::DRAFT;
        assert_eq!(version.as_u32(), 0x8000000c);
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
        let version = ProtocolVersion::RFC;
        assert_eq!(version.as_u32(), 0x00000001);
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
    fn arbitrary_draft_versions_roundtrip() {
        for value in [0x80000001u32, 0x8000000bu32, 0x8000001fu32, 0x80000000u32] {
            let version = ProtocolVersion::from_u32(value)
                .unwrap_or_else(|| panic!("draft 0x{value:08x} must be supported"));
            assert!(version.is_draft());
            assert!(version.is_supported());
            assert_eq!(version.as_u32(), value);

            let mut buf = vec![0u8; version.wire_size()];
            {
                let mut cursor = ParseCursor::new(&mut buf);
                version.to_wire(&mut cursor).unwrap();
            }
            let mut cursor = ParseCursor::new(&mut buf);
            assert_eq!(ProtocolVersion::from_wire(&mut cursor).unwrap(), version);
        }
    }

    #[test]
    fn non_draft_unknown_versions_are_rejected() {
        // The INVALID sentinel and values without the draft flag are not versions
        for value in [0xffffffffu32, 0x7fffffffu32, 0x00000002u32, 0x00000000u32] {
            assert_eq!(ProtocolVersion::from_u32(value), None, "0x{value:08x}");
        }
        assert!(!ProtocolVersion::INVALID.is_draft());
        assert!(!ProtocolVersion::INVALID.is_supported());
    }

    #[test]
    fn version_one_context_strings() {
        // RFC 5.2.1 / 5.2.6: context strings include a terminating zero byte
        assert_eq!(
            ProtocolVersion::RFC.srep_prefix(),
            b"RoughTime v1 response signature\x00"
        );
        assert_eq!(
            ProtocolVersion::RFC.dele_prefix(),
            b"RoughTime v1 delegation signature\x00"
        );
    }

    #[test]
    fn draft_versions_share_context_strings() {
        let draft = ProtocolVersion::from_u32(0x8000000b).unwrap();
        assert_eq!(draft.srep_prefix(), ProtocolVersion::RFC.srep_prefix());
        assert_eq!(draft.dele_prefix(), ProtocolVersion::RFC.dele_prefix());
    }

    #[test]
    fn preference_is_by_recency_not_wire_value() {
        // 0x00000001 outranks 0x8000000c despite the smaller wire value
        assert!(
            ProtocolVersion::RFC.preference() > ProtocolVersion::DRAFT.preference(),
            "RFC version 1 must be preferred over the draft version"
        );

        // RFC version 1 outranks even the highest possible draft
        let max_draft = ProtocolVersion::from_u32(0xfffffffe).unwrap();
        assert!(ProtocolVersion::RFC.preference() > max_draft.preference());
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
    fn negotiation_picks_highest_preference() {
        const RFC: ProtocolVersion = ProtocolVersion::RFC;
        const DRAFT: ProtocolVersion = ProtocolVersion::DRAFT;

        // RFC 5.2.5: the response version SHOULD be one the client offered.
        // Preference is by recency: version 1 outranks the draft version.
        assert_eq!(ProtocolVersion::negotiate(&[RFC]), Some(RFC));
        assert_eq!(ProtocolVersion::negotiate(&[DRAFT]), Some(DRAFT));
        assert_eq!(ProtocolVersion::negotiate(&[RFC, DRAFT]), Some(RFC));
        assert_eq!(ProtocolVersion::negotiate(&[DRAFT, RFC]), Some(RFC));

        // RFC 5.1.1: with no common version the server MAY ignore the request;
        // this implementation signals that with None
        assert_eq!(ProtocolVersion::negotiate(&[]), None);
    }

    #[test]
    fn negotiation_with_arbitrary_drafts() {
        let draft_b = ProtocolVersion::from_u32(0x8000000b).unwrap();
        let draft_c = ProtocolVersion::DRAFT; // 0x8000000c

        // A lone draft is negotiable
        assert_eq!(ProtocolVersion::negotiate(&[draft_b]), Some(draft_b));

        // RFC version 1 outranks any draft
        assert_eq!(
            ProtocolVersion::negotiate(&[ProtocolVersion::RFC, draft_b]),
            Some(ProtocolVersion::RFC)
        );

        // Among drafts, the highest wire value (most recent draft) wins
        assert_eq!(
            ProtocolVersion::negotiate(&[draft_b, draft_c]),
            Some(draft_c)
        );
    }

    #[test]
    fn debug_formatting() {
        assert_eq!(format!("{:?}", ProtocolVersion::RFC), "Rfc");
        assert_eq!(format!("{:?}", ProtocolVersion::DRAFT), "Draft(0x8000000c)");
        assert_eq!(format!("{:?}", ProtocolVersion::INVALID), "Invalid");
        assert_eq!(
            format!("{:?}", ProtocolVersion::from_u32(0x8000000b).unwrap()),
            "Draft(0x8000000b)"
        );
    }

    #[test]
    fn from_str_accepts_version_one() {
        assert_eq!(
            "1".parse::<ProtocolVersion>().unwrap(),
            ProtocolVersion::RFC
        );
    }

    #[test]
    fn from_str_accepts_draft19_names() {
        assert_eq!(
            "19".parse::<ProtocolVersion>().unwrap(),
            ProtocolVersion::DRAFT
        );
        assert_eq!(
            "ietf-roughtime".parse::<ProtocolVersion>().unwrap(),
            ProtocolVersion::RFC
        );
        assert!("google-roughtime".parse::<ProtocolVersion>().is_err());
    }
}
