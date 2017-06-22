
/// An unsigned 32-bit value (key) that maps to a byte-string (value).
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Tag {
    // Enforcement of the "tags in strictly increasing order" rule is done using the
    // little-endian encoding of the ASCII tag value; e.g. 'SIG\x00' is 0x00474953 and
    // 'NONC' is 0x434e4f4e. 

    SIG, NONC, DELE, PATH, RADI, PUBK, MIDP, SREP, MINT, ROOT, CERT, MAXT, INDX, PAD
}

static PAD_VALUE: [u8; 4] = [b'P', b'A', b'D', 0xff];
static SIG_VALUE: [u8; 4] = [b'S', b'I', b'G', 0x00];

impl Tag {
    /// Translates a tag into its on-the-wire representation
    pub fn wire_value(&self) -> &'static [u8] {
        match *self {
            Tag::CERT => "CERT".as_bytes(),
            Tag::DELE => "DELE".as_bytes(),
            Tag::INDX => "INDX".as_bytes(),
            Tag::MAXT => "MAXT".as_bytes(),
            Tag::MIDP => "MIDP".as_bytes(),
            Tag::MINT => "MINT".as_bytes(),
            Tag::NONC => "NONC".as_bytes(),
            Tag::PAD => PAD_VALUE.as_ref(),
            Tag::PATH => "PATH".as_bytes(),
            Tag::PUBK => "PUBK".as_bytes(),
            Tag::RADI => "RADI".as_bytes(),
            Tag::ROOT => "ROOT".as_bytes(),
            Tag::SIG => SIG_VALUE.as_ref(),
            Tag::SREP => "SREP".as_bytes(),
        }
    }
}
