// Copyright 2017-2022 int08h LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::Error;

/// An unsigned 32-bit value (key) that maps to a byte-string (value).
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone, Copy)]
pub enum Tag {
    // Enforcement of the "tags in strictly increasing order" rule is done using the
    // little-endian encoding of the ASCII tag value; e.g. 'SIG\x00' is 0x00474953 and
    // 'NONC' is 0x434e4f4e.
    //
    // Tags are written here in ascending order
    PAD_RFC,
    SIG,
    VER,
    DUT1,
    NONC,
    DELE,
    PATH,
    DTAI,
    RADI,
    PUBK,
    LEAP,
    MIDP,
    SREP,
    MINT,
    ROOT,
    CERT,
    MAXT,
    INDX,
    PAD_CLASSIC,
}

impl Tag {
    const BYTES_CERT: &'static [u8] = b"CERT";
    const BYTES_DELE: &'static [u8] = b"DELE";
    const BYTES_INDX: &'static [u8] = b"INDX";
    const BYTES_MAXT: &'static [u8] = b"MAXT";
    const BYTES_MIDP: &'static [u8] = b"MIDP";
    const BYTES_MINT: &'static [u8] = b"MINT";
    const BYTES_NONC: &'static [u8] = b"NONC";
    const BYTES_PAD_CLASSIC: &'static [u8] = b"PAD\xff";
    const BYTES_PAD_RFC: &'static [u8] = b"PAD\x00";
    const BYTES_PATH: &'static [u8] = b"PATH";
    const BYTES_PUBK: &'static [u8] = b"PUBK";
    const BYTES_RADI: &'static [u8] = b"RADI";
    const BYTES_ROOT: &'static [u8] = b"ROOT";
    const BYTES_SIG: &'static [u8] = b"SIG\x00";
    const BYTES_SREP: &'static [u8] = b"SREP";
    const BYTES_VER: &'static [u8] = b"VER\x00";
    const BYTES_DUT1: &'static [u8] = b"DUT1";
    const BYTES_DTAI: &'static [u8] = b"DTAI";
    const BYTES_LEAP: &'static [u8] = b"LEAP";

    /// Translates a tag into its on-the-wire representation
    pub fn wire_value(self) -> &'static [u8] {
        match self {
            Tag::CERT => Tag::BYTES_CERT,
            Tag::DELE => Tag::BYTES_DELE,
            Tag::INDX => Tag::BYTES_INDX,
            Tag::MAXT => Tag::BYTES_MAXT,
            Tag::MIDP => Tag::BYTES_MIDP,
            Tag::MINT => Tag::BYTES_MINT,
            Tag::NONC => Tag::BYTES_NONC,
            Tag::PAD_CLASSIC => Tag::BYTES_PAD_CLASSIC,
            Tag::PAD_RFC => Tag::BYTES_PAD_RFC,
            Tag::PATH => Tag::BYTES_PATH,
            Tag::PUBK => Tag::BYTES_PUBK,
            Tag::RADI => Tag::BYTES_RADI,
            Tag::ROOT => Tag::BYTES_ROOT,
            Tag::SIG => Tag::BYTES_SIG,
            Tag::SREP => Tag::BYTES_SREP,
            Tag::VER => Tag::BYTES_VER,
            Tag::DUT1 => Tag::BYTES_DUT1,
            Tag::DTAI => Tag::BYTES_DTAI,
            Tag::LEAP => Tag::BYTES_LEAP,
        }
    }

    /// Return the `Tag` corresponding to the on-the-wire representation in `bytes` or an
    /// `Error::InvalidTag` if `bytes` do not correspond to a valid tag.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, Error> {
        match bytes {
            Tag::BYTES_CERT => Ok(Tag::CERT),
            Tag::BYTES_DELE => Ok(Tag::DELE),
            Tag::BYTES_INDX => Ok(Tag::INDX),
            Tag::BYTES_MAXT => Ok(Tag::MAXT),
            Tag::BYTES_MIDP => Ok(Tag::MIDP),
            Tag::BYTES_MINT => Ok(Tag::MINT),
            Tag::BYTES_NONC => Ok(Tag::NONC),
            Tag::BYTES_PAD_CLASSIC => Ok(Tag::PAD_CLASSIC),
            Tag::BYTES_PAD_RFC => Ok(Tag::PAD_RFC),
            Tag::BYTES_PATH => Ok(Tag::PATH),
            Tag::BYTES_PUBK => Ok(Tag::PUBK),
            Tag::BYTES_RADI => Ok(Tag::RADI),
            Tag::BYTES_ROOT => Ok(Tag::ROOT),
            Tag::BYTES_SIG => Ok(Tag::SIG),
            Tag::BYTES_SREP => Ok(Tag::SREP),
            Tag::BYTES_VER => Ok(Tag::VER),
            Tag::BYTES_DUT1 => Ok(Tag::DUT1),
            Tag::BYTES_DTAI => Ok(Tag::DTAI),
            Tag::BYTES_LEAP => Ok(Tag::LEAP),
            _ => Err(Error::InvalidTag(Box::from(bytes))),
        }
    }
}
