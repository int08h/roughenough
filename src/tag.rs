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

use enum_iterator::Sequence;
use std::fmt::{Display, Formatter};

use crate::error::Error;

/// An unsigned 32-bit value (key) that maps to a byte-string (value).
///
/// Tags are ordered by their little-endian encoding of the ASCII tag value.
/// For example, 'SIG\x00' is 0x00474953 and 'NONC' is 0x434e4f4e.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone, Copy, Sequence)]
pub enum Tag {
    // Tags are listed in ascending order based on their wire representation
    SIG,
    VER,
    SRV,
    NONC,
    DELE,
    PATH,
    RADI,
    PUBK,
    MIDP,
    SREP,
    VERS,
    MINT,
    ROOT,
    CERT,
    MAXT,
    INDX,
    ZZZZ,
    PAD,
}

/// Metadata for a tag: wire format and display string.
struct TagData {
    /// The on-the-wire representation of the tag.
    wire: &'static [u8],
    /// The string representation of the tag for display purposes.
    display: &'static str,
}

impl Tag {
    pub(crate) const HASH_PREFIX_SRV: &'static [u8] = &[0xff];

    /// Returns metadata for this tag.
    const fn data(&self) -> TagData {
        match self {
            Tag::SIG => TagData { wire: b"SIG\x00", display: "SIG" },
            Tag::VER => TagData { wire: b"VER\x00", display: "VER" },
            Tag::SRV => TagData { wire: b"SRV\x00", display: "SRV" },
            Tag::NONC => TagData { wire: b"NONC", display: "NONC" },
            Tag::DELE => TagData { wire: b"DELE", display: "DELE" },
            Tag::PATH => TagData { wire: b"PATH", display: "PATH" },
            Tag::RADI => TagData { wire: b"RADI", display: "RADI" },
            Tag::PUBK => TagData { wire: b"PUBK", display: "PUBK" },
            Tag::MIDP => TagData { wire: b"MIDP", display: "MIDP" },
            Tag::SREP => TagData { wire: b"SREP", display: "SREP" },
            Tag::VERS => TagData { wire: b"VERS", display: "VERS" },
            Tag::MINT => TagData { wire: b"MINT", display: "MINT" },
            Tag::ROOT => TagData { wire: b"ROOT", display: "ROOT" },
            Tag::CERT => TagData { wire: b"CERT", display: "CERT" },
            Tag::MAXT => TagData { wire: b"MAXT", display: "MAXT" },
            Tag::INDX => TagData { wire: b"INDX", display: "INDX" },
            Tag::ZZZZ => TagData { wire: b"ZZZZ", display: "ZZZZ" },
            Tag::PAD => TagData { wire: b"PAD\xff", display: "PAD" },
        }
    }

    /// Returns the on-the-wire representation of this tag.
    pub const fn wire_value(&self) -> &'static [u8] {
        self.data().wire
    }

    /// Return the `Tag` corresponding to the on-the-wire representation in `bytes` or an
    /// `Error::InvalidTag` if `bytes` do not correspond to a valid tag.
    pub const fn from_wire(bytes: &[u8]) -> Result<Self, Error> {
        // Wish we could do something like
        //     Tag::SIG.data().wire => Ok(Tag::SIG),
        // to eliminate the duplication
        match bytes {
            b"SIG\x00" => Ok(Tag::SIG),
            b"VER\x00" => Ok(Tag::VER),
            b"SRV\x00" => Ok(Tag::SRV),
            b"NONC" => Ok(Tag::NONC),
            b"DELE" => Ok(Tag::DELE),
            b"PATH" => Ok(Tag::PATH),
            b"RADI" => Ok(Tag::RADI),
            b"PUBK" => Ok(Tag::PUBK),
            b"MIDP" => Ok(Tag::MIDP),
            b"SREP" => Ok(Tag::SREP),
            b"VERS" => Ok(Tag::VERS),
            b"MINT" => Ok(Tag::MINT),
            b"ROOT" => Ok(Tag::ROOT),
            b"CERT" => Ok(Tag::CERT),
            b"MAXT" => Ok(Tag::MAXT),
            b"INDX" => Ok(Tag::INDX),
            b"ZZZZ" => Ok(Tag::ZZZZ),
            b"PAD\xff" => Ok(Tag::PAD),
            _ => Err(Error::InvalidTag),
        }
    }

    /// Returns true if this tag's value is itself an `RtMessage`.
    pub const fn is_nested(&self) -> bool {
        match self {
            Tag::CERT | Tag::DELE | Tag::SREP => true,
            _ => false,
        }
    }

    /// A short (non-canonical) string representation of the tag
    pub const fn as_string(&self) -> &'static str {
        self.data().display
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use enum_iterator;

    #[test]
    fn tags_in_increasing_order() {
        let values = enum_iterator::all::<Tag>().collect::<Vec<_>>();

        // Start from index 1 and compare with the previous element
        for i in 1..values.len() {
            assert!(
                values[i-1] < values[i],
                "Tags not in ascending order: {:?} >= {:?}", values[i-1], values[i]
            );
        }
    }

    #[test]
    fn test_wire_value_and_from_wire() {
        // Test that for each tag, from_wire(wire_value()) is identity
        for tag in enum_iterator::all::<Tag>() {
            let wire = tag.wire_value();
            let roundtrip = Tag::from_wire(wire).unwrap();
            assert_eq!(tag, roundtrip);
        }
    }
}
