use std::fmt::Debug;

use Error::UnorderedVersion;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::protocol_ver::ProtocolVersion;
use crate::wire::{FromWire, FromWireN, ToWire};

/// An ordered list of supported protocol versions. Used by clients in VER, and servers in VERS:
///
/// ```text
/// 5.1.1.  VER
/// In a request, the VER tag contains a list of uint32 version numbers.
/// The VER tag MUST include at least one Roughtime version supported by
/// the client and MUST NOT contain more than 32 version numbers.  The
/// version numbers and tags included in the request MUST be compatible
/// with each other and the packet contents.
///
/// The version numbers MUST NOT repeat and MUST be sorted in ascending
/// numerical order.
/// ```
///
/// ```text
/// 5.2.5.  SREP
/// ...
/// The VERS tag value contains a list of uint32 version numbers
/// supported by the server, sorted in ascending numerical order.  It
/// MUST contain the version number specified in the VER tag.  It MUST
/// NOT contain more than 32 version numbers.
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct VersionList {
    num_versions: usize,
    versions: [ProtocolVersion; VersionList::MAX_VERSIONS],
}

impl VersionList {
    /// Maximum # of versions to hold. Excess versions (if present) will be discarded.
    /// This is intentionally less than the RFC recommended value of 32 which here would
    /// waste an entire 1024 bytes on a mostly empty array.
    pub const MAX_VERSIONS: usize = 8;
}

impl Default for VersionList {
    fn default() -> Self {
        Self {
            num_versions: 0,
            versions: [ProtocolVersion::Invalid; Self::MAX_VERSIONS],
        }
    }
}

impl Debug for VersionList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionList")
            .field("num_versions", &self.num_versions)
            .field("versions", &self.versions())
            .finish()
    }
}

impl VersionList {
    pub fn new(versions: &[ProtocolVersion]) -> Self {
        let count = std::cmp::min(versions.len(), Self::MAX_VERSIONS);

        let mut vers = VersionList {
            num_versions: count,
            ..VersionList::default()
        };
        vers.versions[..count].copy_from_slice(&versions[..count]);

        vers
    }

    pub fn versions(&self) -> &[ProtocolVersion] {
        &self.versions[..self.num_versions]
    }

    pub fn is_supported(&self, version: ProtocolVersion) -> bool {
        self.versions().contains(&version)
    }
}

impl ToWire for VersionList {
    fn wire_size(&self) -> usize {
        self.num_versions * size_of::<ProtocolVersion>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        for version in &self.versions[..self.num_versions] {
            version.to_wire(cursor)?;
        }
        Ok(())
    }
}

impl FromWire for VersionList {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        VersionList::from_wire_n(cursor, cursor.remaining())
    }
}

impl FromWireN for VersionList {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error> {
        let mut remaining = n;
        let mut vers = VersionList::default();
        let mut prior_value = 0u32;
        let mut num_read = 0;
        let mut num_stored = 0;

        while remaining >= size_of::<u32>() && num_read < Self::MAX_VERSIONS {
            let value = cursor.try_get_u32_le()?;

            // Ordering is checked on the raw wire values so that unknown versions
            // participate. This implementation verifies that the versions are in
            // ascending order, but does not consider duplicates an error. That
            // might change in the future.
            if value < prior_value {
                return Err(UnorderedVersion(num_read as u32, value));
            }

            // RFC 5.1.1: "Servers MUST ignore any unknown version numbers in the
            // list supplied by the client."
            if let Some(version) = ProtocolVersion::from_u32(value) {
                vers.versions[num_stored] = version;
                num_stored += 1;
            }

            prior_value = value;
            num_read += 1;
            remaining -= size_of::<u32>();
        }

        vers.num_versions = num_stored;
        Ok(vers)
    }
}

impl From<&[ProtocolVersion]> for VersionList {
    fn from(versions: &[ProtocolVersion]) -> Self {
        VersionList::new(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let versions = VersionList::new(&[ProtocolVersion::RfcDraft19]);

        let wire_size = versions.wire_size();
        let mut buf = vec![0u8; wire_size];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            versions.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let versions2 = VersionList::from_wire(&mut cursor).unwrap();

        assert_eq!(versions, versions2);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn default() {
        let versions = VersionList::default();
        assert!(versions.versions().is_empty());
    }

    #[test]
    fn new() {
        let versions = VersionList::new(&[ProtocolVersion::RfcDraft19]);
        assert_eq!(versions.versions(), &[ProtocolVersion::RfcDraft19]);
        assert!(versions.is_supported(ProtocolVersion::RfcDraft19));
    }

    #[test]
    fn zero_versions() {
        let versions = VersionList::new(&[]);
        assert!(versions.versions().is_empty());
        assert!(!versions.is_supported(ProtocolVersion::RfcDraft19));
    }

    #[test]
    fn max_versions() {
        let tmp = (0..VersionList::MAX_VERSIONS * 2)
            .map(|_| ProtocolVersion::RfcDraft19)
            .collect::<Vec<_>>();

        let versions = VersionList::new(&tmp);

        // overly long input list is truncated to MAX_VERSIONS
        assert_eq!(versions.versions().len(), VersionList::MAX_VERSIONS);
    }

    #[test]
    fn unknown_versions_are_ignored() {
        // RFC 5.1.1: "Servers MUST ignore any unknown version numbers in the list
        // supplied by the client."
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x00000005u32.to_le_bytes());
        buf.extend_from_slice(&(ProtocolVersion::RfcDraft19 as u32).to_le_bytes());

        let mut cursor = ParseCursor::new(&mut buf);
        let versions = VersionList::from_wire(&mut cursor).unwrap();

        assert_eq!(versions.versions(), &[ProtocolVersion::RfcDraft19]);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn all_unknown_versions_yield_empty_list() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x00000005u32.to_le_bytes());
        buf.extend_from_slice(&0x00000006u32.to_le_bytes());
        buf.extend_from_slice(&0x7fffffffu32.to_le_bytes());

        let mut cursor = ParseCursor::new(&mut buf);
        let versions = VersionList::from_wire(&mut cursor).unwrap();

        assert!(versions.versions().is_empty());
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn unknown_versions_must_still_be_ordered() {
        // Ordering is enforced on the raw wire values, unknown or not
        let mut buf = Vec::new();
        buf.extend_from_slice(&(ProtocolVersion::RfcDraft19 as u32).to_le_bytes());
        buf.extend_from_slice(&0x00000005u32.to_le_bytes());

        let mut cursor = ParseCursor::new(&mut buf);
        let result = VersionList::from_wire(&mut cursor);

        match result.unwrap_err() {
            UnorderedVersion(1, 0x00000005) => (), // ok, expected
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn versions_out_of_order() {
        // Wire values in descending order: 0x8000000c followed by 0x00000000
        let mut buf = Vec::new();
        buf.extend_from_slice(&(ProtocolVersion::RfcDraft19 as u32).to_le_bytes());
        buf.extend_from_slice(&0x00000000u32.to_le_bytes());

        // Attempt to deserialize - should fail because versions are not in ascending order
        let mut cursor = ParseCursor::new(&mut buf);
        let result = VersionList::from_wire(&mut cursor);
        assert!(result.is_err(), "out-of-order versions should be rejected");

        match result.unwrap_err() {
            UnorderedVersion(1, _) => (), // ok, expected at index 1
            e => panic!("unexpected error: {e:?}"),
        }
    }
}
