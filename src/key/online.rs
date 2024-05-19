// Copyright 2017-2021 int08h LLC
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

use std::fmt;
use std::fmt::Formatter;
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{LittleEndian, WriteBytesExt};

use crate::message::RtMessage;
use crate::sign::Signer;
use crate::SIGNED_RESPONSE_CONTEXT;
use crate::tag::Tag;
use crate::version::Version;

///
/// Represents the delegated Roughtime ephemeral online key.
///
pub struct OnlineKey {
    signer: Signer,
}

impl Default for OnlineKey {
    fn default() -> Self {
        Self::new()
    }
}

impl OnlineKey {
    pub fn new() -> Self {
        OnlineKey {
            signer: Signer::new(),
        }
    }

    /// Create a DELE message containing the public key of this online key
    pub fn make_dele(&self) -> RtMessage {
        let zeros = [0u8; 8];
        let max = [0xff; 8];
        let pub_key_bytes = self.signer.public_key_bytes();

        let mut dele_msg = RtMessage::with_capacity(3);
        dele_msg.add_field(Tag::PUBK, pub_key_bytes).unwrap();
        dele_msg.add_field(Tag::MINT, &zeros).unwrap();
        dele_msg.add_field(Tag::MAXT, &max).unwrap();

        dele_msg
    }

    /// Classic protocol, epoch time in microseconds
    fn classic_midp(&self, now: SystemTime) -> u64 {
        let d = now
            .duration_since(UNIX_EPOCH)
            .expect("duration since epoch");
        let secs = d.as_secs() * 1_000_000;
        let nsecs = (d.subsec_nanos() as u64) / 1_000;

        secs + nsecs
    }

    /// RFC protocol, a uint64 count of seconds since the Unix epoch in UTC.
    fn rfc_midp(&self, now: SystemTime) -> u64 {
        now.duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Create an SREP response containing the provided time and Merkle root,
    /// signed by this online key.
    pub fn make_srep(&mut self, ver: Version, now: SystemTime, merkle_root: &[u8]) -> RtMessage {
        let mut radi = [0; 4];
        let mut midp = [0; 8];

        let radi_time = match ver {
            Version::Classic => 2_000_000, // two seconds in microseconds
            Version::Rfc => 2, // two seconds
        };

        (&mut radi as &mut [u8])
            .write_u32::<LittleEndian>(radi_time)
            .unwrap();

        let midp_time = match ver {
            Version::Classic => self.classic_midp(now),
            Version::Rfc => self.rfc_midp(now),
        };

        (&mut midp as &mut [u8])
            .write_u64::<LittleEndian>(midp_time)
            .unwrap();

        // Signed response SREP
        let srep_bytes = {
            let mut srep_msg = RtMessage::with_capacity(3);
            srep_msg.add_field(Tag::RADI, &radi).unwrap();
            srep_msg.add_field(Tag::MIDP, &midp).unwrap();
            srep_msg.add_field(Tag::ROOT, merkle_root).unwrap();

            srep_msg.encode().unwrap()
        };

        // signature on SREP
        let srep_signature = {
            self.signer.update(SIGNED_RESPONSE_CONTEXT.as_bytes());
            self.signer.update(&srep_bytes);
            self.signer.sign()
        };

        let mut result = RtMessage::with_capacity(2);
        result.add_field(Tag::SIG, &srep_signature).unwrap();
        result.add_field(Tag::SREP, &srep_bytes).unwrap();

        result
    }
}

impl fmt::Display for OnlineKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.signer)
    }
}
