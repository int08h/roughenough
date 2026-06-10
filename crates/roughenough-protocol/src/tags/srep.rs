use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::{MissingTag, NoSupportedVersions, WrongTagSize};
use crate::header::{Header, Header5, RawHeader};
use crate::tag::Tag;
use crate::tags::{MerkleRoot, ProtocolVersion, SupportedVersions};
use crate::wire::{FromWire, FromWireN, ToWire};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedResponse {
    header: Header5,
    version: ProtocolVersion,
    radius: u32,
    midpoint: u64,
    supported_versions: SupportedVersions,
    merkle_root: MerkleRoot,
}

impl SignedResponse {
    /// Default server accuracy radius in seconds.
    ///
    /// The RADI tag represents the server's estimate of the accuracy of its MIDP (timestamp)
    /// in seconds. Protocol compliant servers must ensure that the true time lies within the
    /// interval (MIDP-RADI, MIDP+RADI) at the moment of processing.
    ///
    /// The RFC states that servers without leap second information should set RADI to
    /// at least 3 seconds. This implementation uses 5 seconds as a conservative default
    /// to account for potential system latency and clock uncertainty. Also leap seconds suck.
    pub const DEFAULT_RADI_SECONDS: u32 = 5;

    const RADI_OFFSET: u32 = size_of::<ProtocolVersion>() as u32;
    const MIDP_OFFSET: u32 = Self::RADI_OFFSET + (size_of::<u32>() as u32);
    const VERS_OFFSET: u32 = Self::MIDP_OFFSET + (size_of::<u64>() as u32);

    // The size of VERS varies, thus the fourth offset (for ROOT) needs to be computed at runtime
    // (in the `set_vers()` method).
    const OFFSETS: [u32; 4] = [Self::RADI_OFFSET, Self::MIDP_OFFSET, Self::VERS_OFFSET, 0];
    const TAGS: [Tag; 5] = [Tag::VER, Tag::RADI, Tag::MIDP, Tag::VERS, Tag::ROOT];

    pub fn header(&self) -> &impl Header {
        &self.header
    }

    pub fn ver(&self) -> &ProtocolVersion {
        &self.version
    }

    pub fn radi(&self) -> u32 {
        self.radius
    }

    pub fn midp(&self) -> u64 {
        self.midpoint
    }

    pub fn vers(&self) -> &SupportedVersions {
        &self.supported_versions
    }

    pub fn root(&self) -> &MerkleRoot {
        &self.merkle_root
    }

    pub fn set_ver(&mut self, version: ProtocolVersion) {
        self.version = version;
    }

    pub fn set_radi(&mut self, radius: u32) {
        self.radius = radius;
    }

    pub fn set_midp(&mut self, midpoint: u64) {
        self.midpoint = midpoint;
    }

    pub fn set_vers(&mut self, versions: &SupportedVersions) {
        self.supported_versions = versions.clone();

        // fix up the offset now that the length of SupportedVersions is known
        self.header.offsets[3] = Self::VERS_OFFSET + (self.supported_versions.wire_size() as u32);
    }

    pub fn set_root(&mut self, root: &MerkleRoot) {
        self.merkle_root = *root;
    }
}

impl Default for SignedResponse {
    fn default() -> Self {
        let mut srep = Self {
            header: Header5::default(),
            version: ProtocolVersion::Invalid,
            radius: 0,
            midpoint: 0,
            supported_versions: SupportedVersions::default(),
            merkle_root: MerkleRoot::default(),
        };

        // The fourth offset will be set once the length of SupportedVersions is known.
        // See `SignedResponse::set_vers()`
        srep.header.offsets = Self::OFFSETS;
        srep.header.tags = Self::TAGS;
        srep
    }
}

impl ToWire for SignedResponse {
    fn wire_size(&self) -> usize {
        self.header.wire_size()
            + self.version.wire_size()
            + size_of::<u32>()
            + size_of::<u64>()
            + self.supported_versions.wire_size()
            + self.merkle_root.wire_size()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.header.to_wire(cursor)?;
        self.version.to_wire(cursor)?;
        cursor.put_u32_le(self.radius);
        cursor.put_u64_le(self.midpoint);
        self.supported_versions.to_wire(cursor)?;
        self.merkle_root.to_wire(cursor)?;
        Ok(())
    }
}

impl FromWire for SignedResponse {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let msg_len = cursor.remaining();
        Self::from_wire_n(cursor, msg_len)
    }
}

impl FromWireN for SignedResponse {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error> {
        const RAW_VER: u32 = Tag::VER as u32;
        const RAW_RADI: u32 = Tag::RADI as u32;
        const RAW_MIDP: u32 = Tag::MIDP as u32;
        const RAW_VERS: u32 = Tag::VERS as u32;
        const RAW_ROOT: u32 = Tag::ROOT as u32;

        let header = RawHeader::from_wire_n(cursor, n)?;

        let mut version: Option<ProtocolVersion> = None;
        let mut radius: Option<u32> = None;
        let mut midpoint: Option<u64> = None;
        let mut supported_versions: Option<SupportedVersions> = None;
        let mut merkle_root: Option<MerkleRoot> = None;

        for (raw_tag, value_len) in header.entries() {
            let value_start = cursor.position();

            match raw_tag {
                RAW_VER => {
                    if value_len != size_of::<u32>() {
                        return Err(WrongTagSize(size_of::<u32>(), value_len));
                    }
                    version = Some(ProtocolVersion::from_wire(cursor)?);
                }
                RAW_RADI => {
                    if value_len != size_of::<u32>() {
                        return Err(WrongTagSize(size_of::<u32>(), value_len));
                    }
                    radius = Some(cursor.try_get_u32_le()?);
                }
                RAW_MIDP => {
                    if value_len != size_of::<u64>() {
                        return Err(WrongTagSize(size_of::<u64>(), value_len));
                    }
                    midpoint = Some(cursor.try_get_u64_le()?);
                }
                RAW_VERS => {
                    if value_len == 0 {
                        return Err(NoSupportedVersions);
                    }
                    supported_versions = Some(SupportedVersions::from_wire_n(cursor, value_len)?);
                }
                RAW_ROOT => {
                    if value_len != size_of::<MerkleRoot>() {
                        return Err(WrongTagSize(size_of::<MerkleRoot>(), value_len));
                    }
                    merkle_root = Some(MerkleRoot::from_wire(cursor)?);
                }
                // RFC 9.2 adds new tags to SREP; RFC 7: clients MUST properly
                // ignore undefined tags
                _ => {}
            }

            cursor.set_position(value_start + value_len);
        }

        let mut srep = SignedResponse::default();
        srep.set_ver(version.ok_or(MissingTag("VER"))?);
        srep.set_radi(radius.ok_or(MissingTag("RADI"))?);
        srep.set_midp(midpoint.ok_or(MissingTag("MIDP"))?);
        srep.set_vers(&supported_versions.ok_or(MissingTag("VERS"))?);
        srep.set_root(&merkle_root.ok_or(MissingTag("ROOT"))?);

        Ok(srep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::{MerkleRoot, ProtocolVersion, SupportedVersions};

    fn create_valid_signed_response() -> SignedResponse {
        let mut srep = SignedResponse::default();
        srep.set_ver(ProtocolVersion::RfcDraft19);
        srep.set_radi(5);
        srep.set_midp(1234567);
        srep.set_vers(&SupportedVersions::new(&[ProtocolVersion::RfcDraft19]));
        srep.set_root(&MerkleRoot::from([0x2e; 32]));

        srep
    }

    #[test]
    fn default_value() {
        let srep = SignedResponse::default();
        assert_eq!(srep.ver(), &ProtocolVersion::Invalid);
        assert_eq!(srep.radi(), 0);
        assert_eq!(srep.midp(), 0);
        assert_eq!(srep.vers(), &SupportedVersions::default());
        assert_eq!(srep.root(), &MerkleRoot::default());
    }

    #[test]
    fn wire_roundtrip() {
        let srep1 = create_valid_signed_response();
        let mut buf = vec![0u8; srep1.wire_size()];
        {
            let mut cursor = ParseCursor::new(&mut buf);
            srep1.to_wire(&mut cursor).unwrap();
        }
        let mut cursor = ParseCursor::new(&mut buf);
        let srep2 = SignedResponse::from_wire(&mut cursor).unwrap();

        assert_eq!(srep1, srep2);
    }

    #[test]
    fn missing_required_tag_is_detected() {
        let mut srep = create_valid_signed_response();
        let mut buf = vec![0u8; srep.wire_size()];

        // Replace ROOT with a tag that is undefined in SREP. The undefined tag
        // is ignored, leaving the required ROOT tag missing.
        srep.header.tags[4] = Tag::INDX;
        {
            let mut cursor = ParseCursor::new(&mut buf);
            srep.to_wire(&mut cursor).unwrap();
        }
        let mut cursor = ParseCursor::new(&mut buf);

        let result = SignedResponse::from_wire(&mut cursor);

        match result {
            Err(MissingTag("ROOT")) => (), // ok, expected
            _ => panic!("unexpected result: {result:?}"),
        }
    }
}
