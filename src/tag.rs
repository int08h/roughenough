#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Tag {
    CERT,
    DELE,
    INDX,
    MAXT,
    MIDP,
    MINT,
    NONC,
    PAD,
    PATH,
    PUBK,
    RADI,
    ROOT,
    SIG,
    SREP,
}

static PAD_VALUE: [u8; 4] = [b'P', b'A', b'D', 0x00];
static SIG_VALUE: [u8; 4] = [b'S', b'I', b'G', 0xff];

impl Tag {
    pub fn wire_value(&self) -> &'static [u8] {
        match *self {
            Tag::CERT => "CERT".as_bytes(),
            Tag::DELE => "DELE".as_bytes(),
            Tag::INDX => "INDX".as_bytes(),
            Tag::MAXT => "MAXT".as_bytes(),
            Tag::MIDP => "MIDP".as_bytes(),
            Tag::MINT => "MINT".as_bytes(),
            Tag::NONC => "NONC".as_bytes(),
            Tag::PAD =>  PAD_VALUE.as_ref(),
            Tag::PATH => "PATH".as_bytes(),
            Tag::PUBK => "PUBK".as_bytes(),
            Tag::RADI => "RADI".as_bytes(),
            Tag::ROOT => "ROOT".as_bytes(),
            Tag::SIG => SIG_VALUE.as_ref(),
            Tag::SREP => "SREP".as_bytes(),
        }
    }
}
