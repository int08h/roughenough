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

mod envelope;
mod longterm;
mod online;

use std::error::Error;
use std::str::FromStr;

pub use self::envelope::EnvelopeEncryption;
pub use self::longterm::LongTermKey;
pub use self::online::OnlineKey;

use super::config::ServerConfig;
use super::error;

#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone)]
pub enum KeyProtection {
    /// No protection, seed is in plaintext
    Plaintext,

    /// Envelope encryption using AWS Key Management Service
    AwsKmsEnvelope(String),

    /// Envelope encryption using Google Cloud Key Management Service
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone)]
pub enum KmsError {
    OperationFailed(String),
    InvalidConfiguration(String),
    InvalidData(String),
    InvalidKey(String),
}

impl From<std::io::Error> for KmsError {
    fn from(error: std::io::Error) -> Self {
        KmsError::OperationFailed(error.description().to_string())
    }
}

impl From<ring::error::Unspecified> for KmsError {
    fn from(_: ring::error::Unspecified) -> Self {
        KmsError::OperationFailed("unspecified ring cryptographic failure".to_string())
    }
}

/// Size of the Data Encryption Key (DEK) in bytes
pub const DEK_SIZE_BYTES: usize = 32;

/// Size of the AEAD nonce in bytes
pub const NONCE_SIZE_BYTES: usize = 12;

/// Size of the AEAD authentication tag in bytes
pub const TAG_SIZE_BYTES: usize = 16;

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

#[cfg(feature = "kms")]
pub mod awskms;

#[cfg(feature = "kms")]
use key::awskms::AwsKms;
use std::fmt::Display;
use std::fmt::Formatter;

#[cfg(feature = "kms")]
pub fn load_seed(config: &Box<ServerConfig>) -> Result<Vec<u8>, error::Error> {
    match config.key_protection() {
        KeyProtection::Plaintext => Ok(config.seed()),
        KeyProtection::AwsKmsEnvelope(key_id) => {
            info!("Unwrapping seed via AWS KMS key '{}'", key_id);
            let kms = AwsKms::from_arn(key_id)?;
            let seed = EnvelopeEncryption::decrypt_seed(&kms, &config.seed())?;
            Ok(seed)
        }
        _ => Err(error::Error::InvalidConfiguration(
            "Google KMS not supported".to_string(),
        )),
    }
}

#[cfg(not(feature = "kms"))]
pub fn load_seed(config: &Box<ServerConfig>) -> Result<Vec<u8>, error::Error> {
    match config.key_protection() {
        KeyProtection::Plaintext => Ok(config.seed()),
        v => Err(error::Error::InvalidConfiguration(format!(
            "key_protection '{}' implies KMS but server was not compiled with KMS support", v
        ))),
    }
}
