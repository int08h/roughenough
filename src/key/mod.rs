// Copyright 2017-2018 int08h LLC
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

//!
//! Representations and management of Roughtime's online and long-term Ed25519 keys
//!

extern crate hex;
extern crate log;
extern crate ring;
extern crate std;

mod longterm;
mod online;

use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

pub use self::longterm::LongTermKey;
pub use self::online::OnlineKey;

/// Methods for protecting the server's long-term identity
#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone)]
pub enum KeyProtection {
    /// No protection, seed is in plaintext
    Plaintext,

    /// Envelope encryption of the seed using AWS Key Management Service
    AwsKmsEnvelope(String),

    /// Envelope encryption of the seed using Google Cloud Key Management Service
    GoogleKmsEnvelope(String),
}

impl Display for KeyProtection {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            KeyProtection::Plaintext => write!(f, "Plaintext"),
            KeyProtection::AwsKmsEnvelope(key_id) => write!(f, "AwsKms({})", key_id),
            KeyProtection::GoogleKmsEnvelope(key_id) => write!(f, "GoogleKms({})", key_id),
        }
    }
}

impl FromStr for KeyProtection {
    type Err = ();

    fn from_str(s: &str) -> Result<KeyProtection, ()> {
        match s {
            "plaintext" => Ok(KeyProtection::Plaintext),
            s if s.starts_with("arn") => Ok(KeyProtection::AwsKmsEnvelope(s.to_string())),
            s if s.starts_with("gcp") => Ok(KeyProtection::GoogleKmsEnvelope(s.to_string())),
            _ => Err(()),
        }
    }
}

