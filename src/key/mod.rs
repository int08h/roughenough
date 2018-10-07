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

mod longterm;
mod online;

pub use self::longterm::LongTermKey;
pub use self::online::OnlineKey;

#[cfg(feature = "kms")]
pub mod awskms;

#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone, Copy)]
pub enum KeyProtection {
    /// No protection, seed is in plaintext
    Plaintext,

    /// Envelope encryption of seed by AWS Key Management Service
    AwsKmsEnvelope,

    /// Envelope encryption of seed by Google Cloud Key Management Service
    GoogleKmsEnvelope,
}
