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
    Google,

    /// IETF draft version 13 (placeholder for final IETF standardized version)
    RfcDraft13,
}

struct VersionData {
    wire: &'static [u8],
    display: &'static str,
    dele_prefix: &'static [u8],
    srep_prefix: &'static [u8],
}

impl Version {
    const fn data(&self) -> VersionData {
        match self {
            Version::Google => VersionData {
                wire: &[0x00, 0x00, 0x00, 0x00],
                display: "Google",
                dele_prefix: b"RoughTime v1 delegation signature--\x00",
                srep_prefix: b"RoughTime v1 response signature\x00",
            },
            Version::RfcDraft13 => VersionData {
                wire: &[0x0c, 0x00, 0x00, 0x80],
                display: "RfcDraft13",
                dele_prefix: b"RoughTime v1 delegation signature\x00",
                srep_prefix: b"RoughTime v1 response signature\x00",
            },
        }
    }

    /// Ordered (ascending) on-the-wire bytes of supported versions (`VERS` tag value)
    pub fn supported_versions_wire() -> Vec<u8> {
        [
            Version::Google.wire_bytes(),
            Version::RfcDraft13.wire_bytes(),
        ]
        .concat()
    }

    /// On-the-wire representation of the `Version`
    pub const fn wire_bytes(&self) -> &'static [u8] {
        self.data().wire
    }

    /// A short (non-canonical) string representation of the `Version`
    pub const fn as_string(&self) -> &'static str {
        self.data().display
    }

    /// Domain separator prefixed to the server's `DELE` value before generating or
    /// verifying the signature
    pub const fn dele_prefix(&self) -> &'static [u8] {
        self.data().dele_prefix
    }

    /// Domain separator prefixed to the server's `SREP` value before generating or
    /// verifying the signature
    pub const fn sign_prefix(&self) -> &'static [u8] {
        self.data().srep_prefix
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}
