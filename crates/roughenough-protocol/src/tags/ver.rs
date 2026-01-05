use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::protocol_ver::ProtocolVersion;
use crate::version_list::VersionList;
use crate::wire::{FromWire, FromWireN, ToWire};

/// The `VER` tag contains a list of uint32 Roughtime protocol version numbers.
///
/// ```text
/// 5.1.1.  VER
/// In a request, the VER tag contains a list of uint32 version numbers.
/// The VER tag MUST include at least one Roughtime version supported by
/// the client and MUST NOT contain more than 32 version numbers.  The
/// client MUST ensure that the version numbers and tags included in the
/// request are not incompatible with each other or the packet contents.
///
/// The version numbers MUST NOT repeat and MUST be sorted in ascending
/// numerical order.
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct RequestedVersions {
    versions: VersionList,
}

impl Default for RequestedVersions {
    fn default() -> Self {
        Self {
            versions: VersionList::new(&[ProtocolVersion::RfcDraft14]),
        }
    }
}

impl Debug for RequestedVersions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VER")
            .field("versions", &self.versions())
            .finish()
    }
}

impl RequestedVersions {
    pub fn new(versions: &[ProtocolVersion]) -> Self {
        let versions = VersionList::new(versions);
        Self { versions }
    }

    pub fn versions(&self) -> &[ProtocolVersion] {
        self.versions.versions()
    }

    pub fn is_supported(&self, version: ProtocolVersion) -> bool {
        self.versions().contains(&version)
    }
}

impl ToWire for RequestedVersions {
    fn wire_size(&self) -> usize {
        self.versions.wire_size()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.versions.to_wire(cursor)?;
        Ok(())
    }
}

impl FromWire for RequestedVersions {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        RequestedVersions::from_wire_n(cursor, cursor.remaining())
    }
}

impl FromWireN for RequestedVersions {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error> {
        let versions = VersionList::from_wire_n(cursor, n)?;
        Ok(Self { versions })
    }
}

impl From<&[ProtocolVersion]> for RequestedVersions {
    fn from(versions: &[ProtocolVersion]) -> Self {
        RequestedVersions::new(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let versions =
            RequestedVersions::new(&[ProtocolVersion::Google, ProtocolVersion::RfcDraft14]);

        let wire_size = versions.wire_size();
        let mut buf = vec![0u8; wire_size];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            versions.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let versions2 = RequestedVersions::from_wire(&mut cursor).unwrap();

        assert_eq!(versions, versions2);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn default() {
        let versions = RequestedVersions::default();
        assert_eq!(versions.versions(), &[ProtocolVersion::RfcDraft14]);
    }

    #[test]
    fn new() {
        let versions = RequestedVersions::new(&[ProtocolVersion::Google]);
        assert_eq!(versions.versions(), &[ProtocolVersion::Google]);
        assert!(versions.is_supported(ProtocolVersion::Google));
        assert!(!versions.is_supported(ProtocolVersion::RfcDraft14));
    }

    #[test]
    fn zero_versions() {
        let versions = RequestedVersions::new(&[]);
        assert!(versions.versions().is_empty());
        assert!(!versions.is_supported(ProtocolVersion::Google));
        assert!(!versions.is_supported(ProtocolVersion::RfcDraft14));
    }
}
