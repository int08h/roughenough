/// RFC 4.1.3: Tags are used to identify values in Roughtime messages.
///
/// An unsigned 32-bit value (key) that maps to a byte-string (value).
///
/// Tags are ordered by their little-endian encoding of the ASCII tag value.
/// For example, 'SIG\x00' is 0x00474953 and 'NONC' is 0x434e4f4e. Tags are
/// serialized to the wire in big-endian order.
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Tag {
    INVALID = 0x00000000,
    SIG = 0x53494700,
    VER = 0x56455200,
    SRV = 0x53525600,
    NONC = 0x4e4f4e43,
    DELE = 0x44454c45,
    TYPE = 0x54595045,
    PATH = 0x50415448,
    RADI = 0x52414449,
    PUBK = 0x5055424b,
    MIDP = 0x4d494450,
    SREP = 0x53524550,
    VERS = 0x56455253,
    MINT = 0x4d494e54,
    ROOT = 0x524f4f54,
    CERT = 0x43455254,
    MAXT = 0x4d415854,
    INDX = 0x494e4458,
    ZZZZ = 0x5a5a5a5a,
    PAD = 0x504144ff,
}

impl Tag {
    /// Returns the on-the-wire representation of this tag.
    pub const fn wire_value(&self) -> [u8; 4] {
        let value = *self as u32;
        value.to_be_bytes()
    }

    /// The ASCII name of this tag
    pub const fn name(&self) -> &'static str {
        match self {
            Tag::INVALID => "INVALID",
            Tag::SIG => "SIG",
            Tag::VER => "VER",
            Tag::SRV => "SRV",
            Tag::NONC => "NONC",
            Tag::DELE => "DELE",
            Tag::TYPE => "TYPE",
            Tag::PATH => "PATH",
            Tag::RADI => "RADI",
            Tag::PUBK => "PUBK",
            Tag::MIDP => "MIDP",
            Tag::SREP => "SREP",
            Tag::VERS => "VERS",
            Tag::MINT => "MINT",
            Tag::ROOT => "ROOT",
            Tag::CERT => "CERT",
            Tag::MAXT => "MAXT",
            Tag::INDX => "INDX",
            Tag::ZZZZ => "ZZZZ",
            Tag::PAD => "PAD",
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn wire_value_is_ascii_name() {
        let tags = [
            Tag::SIG,
            Tag::VER,
            Tag::SRV,
            Tag::NONC,
            Tag::DELE,
            Tag::TYPE,
            Tag::PATH,
            Tag::RADI,
            Tag::PUBK,
            Tag::MIDP,
            Tag::SREP,
            Tag::VERS,
            Tag::MINT,
            Tag::ROOT,
            Tag::CERT,
            Tag::MAXT,
            Tag::INDX,
            Tag::ZZZZ,
            Tag::PAD,
        ];
        for tag in tags {
            assert!(
                tag.wire_value().starts_with(tag.name().as_bytes()),
                "{tag:?} wire value {:02x?} does not start with {:?}",
                tag.wire_value(),
                tag.name()
            );
        }
    }
}
