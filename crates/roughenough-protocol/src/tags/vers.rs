use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::protocol_ver::ProtocolVersion;
use crate::version_list::VersionList;
use crate::wire::{FromWire, FromWireN, ToWire};

#[derive(Default, Clone, PartialEq, Eq)]
pub struct SupportedVersions {
    versions: VersionList,
}

impl Debug for SupportedVersions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VERS")
            .field("versions", &self.versions())
            .finish()
    }
}

impl SupportedVersions {
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

impl ToWire for SupportedVersions {
    fn wire_size(&self) -> usize {
        self.versions.wire_size()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.versions.to_wire(cursor)?;
        Ok(())
    }
}

impl FromWire for SupportedVersions {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        SupportedVersions::from_wire_n(cursor, cursor.remaining())
    }
}

impl FromWireN for SupportedVersions {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error> {
        let versions = VersionList::from_wire_n(cursor, n)?;
        Ok(Self { versions })
    }
}

impl From<&[ProtocolVersion]> for SupportedVersions {
    fn from(versions: &[ProtocolVersion]) -> Self {
        SupportedVersions::new(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let versions =
            SupportedVersions::new(&[ProtocolVersion::Google, ProtocolVersion::RfcDraft14]);

        let wire_size = versions.wire_size();
        let mut buf = vec![0u8; wire_size];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            versions.to_wire(&mut cursor).unwrap();
        }

        let mut cursor = ParseCursor::new(&mut buf);
        let versions2 = SupportedVersions::from_wire(&mut cursor).unwrap();

        assert_eq!(versions, versions2);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn default() {
        let versions = SupportedVersions::default();
        assert!(versions.versions().is_empty());
    }

    #[test]
    fn new() {
        let versions = SupportedVersions::new(&[ProtocolVersion::Google]);
        assert_eq!(versions.versions(), &[ProtocolVersion::Google]);
        assert!(versions.is_supported(ProtocolVersion::Google));
        assert!(!versions.is_supported(ProtocolVersion::RfcDraft14));
    }

    #[test]
    fn zero_versions() {
        let versions = SupportedVersions::new(&[]);
        assert!(versions.versions().is_empty());
        assert!(!versions.is_supported(ProtocolVersion::Google));
        assert!(!versions.is_supported(ProtocolVersion::RfcDraft14));
    }
}
