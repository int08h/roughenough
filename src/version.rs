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

use std::fmt::{Display, Formatter};

/// Version of the Roughtime protocol
#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone, Copy)]
pub enum Version {
    /// Original Google version from https://roughtime.googlesource.com/roughtime/+/HEAD/PROTOCOL.md
    Classic,

    /// Placeholder for final IETF standardized version
    Rfc,

    /// IETF draft version 11
    RfcDraft11,
}

// Google classic (unused)
const BYTES_VER_CLASSIC: &'static [u8] = &[0x00, 0x00, 0x00, 0x00];
const STR_VER_CLASSIC: &'static str = "Classic";

// RFC version 1
const BYTES_VER_RFC: &'static [u8] = &[0x01, 0x00, 0x00, 0x00];
const STR_VER_RFC: &'static str = "Rfc";

// RFC draft 11 (keep updated as draft evolves)
const BYTES_VER_RFC_DRAFT11: &'static [u8] = &[0x0b, 0x00, 0x00, 0x80];
const STR_VER_RFC_DRAFT11: &'static str = "RfcDraft11";

impl Version {
    /// On-the-wire representation of the version value
    pub const fn wire_bytes(self) -> &'static [u8] {
        match self {
            Version::Classic => BYTES_VER_CLASSIC,
            Version::Rfc => BYTES_VER_RFC,
            Version::RfcDraft11 => BYTES_VER_RFC_DRAFT11,
        }
    }

    /// A short (non-canonical) string representation of the `Version`
    pub const fn to_string(&self) -> &'static str {
        match self {
            Version::Classic => STR_VER_CLASSIC,
            Version::Rfc => STR_VER_RFC,
            Version::RfcDraft11 => STR_VER_RFC_DRAFT11,
        }
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
