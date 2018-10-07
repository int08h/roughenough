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

mod envelope;
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

    /// Envelope encryption with Key-Encrypting-Key (KEK) from AWS Key Management Service
    AwsKmsEnvelope,

    /// Envelope encryption with Key-Encrypting-Key (KEK) from Google Cloud Key Management Service
    GoogleKmsEnvelope,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone, Copy)]
pub enum KmsError {
    DecryptionFailed(String),
    EncryptionFailed(String),
    InvalidConfiguration(String),
    InvalidKey(String),
}

/// Size of the Data Encryption Key (DEK) in bytes
pub const DEK_SIZE_BYTES: usize = 32;

/// An unencrypted (plaintext) 256-bit Data Encryption Key (DEK).
type PlaintextDEK = Vec<u8>;

/// A Data Encryption Key (DEK) that has been encrypted (wrapped) by a Key Encryption Key (KEK).
/// Size of the encrypted DEK is implementation specific (things like AEAD tag size, nonce size,
/// provider metadata, and so on will cause it to vary).
type EncryptedDEK = Vec<u8>;

pub trait KmsProvider {
    fn encrypt_dek(&self, plaintext_dek: &PlaintextDEK) -> Result<EncryptedDEK, KmsError>;
    fn decrypt_dek(&self, encrypted_dek: &EncryptedDEK) -> Result<PlaintextDEK, KmsError>;
}
