// Copyright 2017 int08h LLC
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

/// An unsigned 32-bit value (key) that maps to a byte-string (value).
#[derive(Debug, PartialEq, PartialOrd)]
pub enum Tag {
    // Enforcement of the "tags in strictly increasing order" rule is done using the
    // little-endian encoding of the ASCII tag value; e.g. 'SIG\x00' is 0x00474953 and
    // 'NONC' is 0x434e4f4e. 
    //
    // Tags are written here in ascending order
    SIG,
    NONC,
    DELE,
    PATH,
    RADI,
    PUBK,
    MIDP,
    SREP,
    MINT,
    ROOT,
    CERT,
    MAXT,
    INDX,
    PAD,
}

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
            Tag::PAD => [b'P', b'A', b'D', 0xff].as_ref(),
            Tag::PATH => "PATH".as_bytes(),
            Tag::PUBK => "PUBK".as_bytes(),
            Tag::RADI => "RADI".as_bytes(),
            Tag::ROOT => "ROOT".as_bytes(),
            Tag::SIG => [b'S', b'I', b'G', 0x00].as_ref(),
            Tag::SREP => "SREP".as_bytes(),
        }
    }
}
