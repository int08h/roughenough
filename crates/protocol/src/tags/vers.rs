use std::fmt::Debug;

use Error::UnorderedVersion;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::tags::ver::Version;
use crate::wire::{FromWire, FromWireN, ToWire};

#[derive(Clone, PartialEq, Eq)]
pub struct SupportedVersions {
    num_versions: usize,
    versions: [Version; SupportedVersions::MAX_VERSIONS],
}

impl SupportedVersions {
    /// Maximum # of versions to hold. Excess versions (if present) will be discarded.
    pub const MAX_VERSIONS: usize = 4;
}

impl Default for SupportedVersions {
    fn default() -> Self {
        Self {
            num_versions: 0,
            versions: [Version::Invalid; Self::MAX_VERSIONS],
        }
    }
}

impl Debug for SupportedVersions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VERS")
            .field("num_versions", &self.num_versions)
            .field("versions", &self.versions())
            .finish()
    }
}

impl SupportedVersions {
    pub fn new(versions: &[Version]) -> Self {
        let count = std::cmp::min(versions.len(), Self::MAX_VERSIONS);

        let mut vers = SupportedVersions {
            num_versions: count,
            ..SupportedVersions::default()
        };
        vers.versions[..count].copy_from_slice(&versions[..count]);

        vers
    }

    pub fn versions(&self) -> &[Version] {
        &self.versions[..self.num_versions]
    }

    pub fn is_supported(&self, version: Version) -> bool {
        self.versions().contains(&version)
    }
}

impl ToWire for SupportedVersions {
    fn wire_size(&self) -> usize {
        self.num_versions * size_of::<Version>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        for version in &self.versions[..self.num_versions] {
            version.to_wire(cursor)?;
        }
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
        let mut remaining = n;
        let mut vers = SupportedVersions::default();
        let mut prior_version = Version::Google;
        let mut index = 0;

        while remaining > 0 && index < Self::MAX_VERSIONS {
            let version = Version::from_wire(cursor)?;

            if version < prior_version {
                return Err(UnorderedVersion(index as u32, version as u32));
            }

            vers.versions[index] = version;
            prior_version = version;
            index += 1;
            remaining -= version.wire_size();
        }

        vers.num_versions = index;
        Ok(vers)
    }
}

impl From<&[Version]> for SupportedVersions {
    fn from(versions: &[Version]) -> Self {
        SupportedVersions::new(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let versions = SupportedVersions::new(&[Version::Google, Version::RfcDraft14]);

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
        let versions = SupportedVersions::new(&[Version::Google]);
        assert_eq!(versions.versions(), &[Version::Google]);
        assert!(versions.is_supported(Version::Google));
        assert!(!versions.is_supported(Version::RfcDraft14));
    }

    #[test]
    fn zero_versions() {
        let versions = SupportedVersions::new(&[]);
        assert!(versions.versions().is_empty());
        assert!(!versions.is_supported(Version::Google));
        assert!(!versions.is_supported(Version::RfcDraft14));
    }

    #[test]
    fn max_versions() {
        let versions = SupportedVersions::new(&[
            Version::Google,
            Version::RfcDraft14,
            Version::Google,
            Version::RfcDraft14,
            Version::Google,
            Version::RfcDraft14,
            Version::Google,
            Version::RfcDraft14,
            Version::Google,
            Version::RfcDraft14,
            Version::Google,
            Version::RfcDraft14,
        ]);

        assert_eq!(versions.versions().len(), SupportedVersions::MAX_VERSIONS);
    }
}
