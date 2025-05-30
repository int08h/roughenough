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

//!
//! Protect the server's long-term key with envelope encryption and a key management system.
//!
//! Note: KMS support must be enabled at compile time, see the Roughenough's [documentation
//! on optional features](https://github.com/int08h/roughenough/blob/master/doc/OPTIONAL-FEATURES.md#key-management-system-kms-support)
//! for instructions.
//!
//! ## Motivation
//!
//! The seed for the server's [long-term key](../key/struct.LongTermKey.html) is subject to
//! contradictory requirements:
//!
//!   1. The seed must be kept secret, but
//!   2. The seed must be available at server start-up to create the
//!      [delegated on-line key](../key/struct.OnlineKey.html)
//!
//! ## Plaintext seed
//!
//! The default option is to store the seed in plaintext as part of the server's configuration.
//! This usually means the seed is present in the clear: on disk, in a repository, or otherwise
//! durably persisted where it can be compromised (accidentally or maliciously).
//!
//! ## Encrypting the seed
//!
//! Envelope encryption protects the seed by encrypting it with a locally generated 256-bit
//! Data Encryption Key (DEK). The DEK itself is then encrypted using a cloud key management
//! system (KMS). The resulting opaque encrypted "blob" (encrypted seed + encrypted DEK) is
//! stored in the Roughenough configuration.
//!
//! At server start-up the KMS is used to decrypt the DEK, which is then used to (in memory)
//! decrypt the seed. The seed is used to generate the
//! [delegated on-line key](../key/struct.OnlineKey.html) after which the seed and DEK are erased
//! from memory.
//!
//! See
//!   * [`EnvelopeEncryption`](struct.EnvelopeEncryption.html) for Roughenough's implementation.
//!   * [Google](https://cloud.google.com/kms/docs/envelope-encryption) or
//!     [Amazon](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping)
//!     for more in-depth explanations of envelope encryption.
//!

use std;

use data_encoding;
use aws_lc_rs;

use crate::config::ServerConfig;
use crate::error;
use crate::key::KmsProtection;
#[cfg(feature = "awskms")]
pub use crate::kms::awskms::inner::AwsKms;
#[cfg(feature = "gcpkms")]
pub use crate::kms::gcpkms::inner::GcpKms;

pub use self::envelope::EnvelopeEncryption;

mod envelope;

/// Errors generated by KMS operations
#[derive(Debug, PartialEq, Eq, PartialOrd, Hash, Clone)]
pub enum KmsError {
    OperationFailed(String),
    InvalidConfiguration(String),
    InvalidData(String),
    InvalidKey(String),
}

impl From<std::io::Error> for KmsError {
    fn from(error: std::io::Error) -> Self {
        KmsError::OperationFailed(format!("{:?}", error))
    }
}

impl From<aws_lc_rs::error::Unspecified> for KmsError {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        KmsError::OperationFailed("unspecified cryptographic failure".to_string())
    }
}

impl From<data_encoding::DecodeError> for KmsError {
    fn from(error: data_encoding::DecodeError) -> Self {
        KmsError::OperationFailed(format!("base64: {}", error))
    }
}

// Size of the AEAD nonce in bytes.
const NONCE_LEN_BYTES: usize = 12;

// Size of the AEAD authentication tag in bytes.
const TAG_LEN_BYTES: usize = 16;

// Size of the 256-bit Data Encryption Key (DEK) in bytes.
const DEK_LEN_BYTES: usize = 32;

// Trivial domain separation to guard against KMS key reuse
const AD: &str = "roughenough";

/// An unencrypted (plaintext) 256-bit Data Encryption Key (DEK).
pub type PlaintextDEK = Vec<u8>;

/// A Data Encryption Key (DEK) that has been encrypted (wrapped) by a Key Management System (KMS).
///
/// This is an opaque, implementation-specific value. AEAD tag size, nonce size,
/// provider metadata, and so on will vary between [`KmsProvider`](trait.KmsProvider.html)
/// implementations.
pub type EncryptedDEK = Vec<u8>;

///
/// A key management system that wraps/unwraps a data encryption key (DEK).
///
pub trait KmsProvider {
    /// Make a blocking request to encrypt (wrap) the provided plaintext data encryption key.
    fn encrypt_dek(&self, plaintext_dek: &PlaintextDEK) -> Result<EncryptedDEK, KmsError>;

    /// Make a blocking request to decrypt (unwrap) a previously encrypted data encryption key.
    fn decrypt_dek(&self, encrypted_dek: &EncryptedDEK) -> Result<PlaintextDEK, KmsError>;
}

#[cfg(feature = "awskms")]
mod awskms;

/// Load the seed value for the long-term key.
///
/// Loading behavior depends on the value of `config.kms_protection()`:
///
///  * If `config.kms_protection() == Plaintext` then the value returned from `config.seed()`
///    is used as-is and assumed to be a 32-byte hexadecimal value.
///
///  * Otherwise `config.seed()` is assumed to be an encrypted opaque blob generated from
///    a prior `EnvelopeEncryption::encrypt_seed` call. The value of `config.kms_protection()`
///    is parsed as a KMS key id and `EnvelopeEncryption::decrypt_seed` is called to obtain
///    the plaintext seed value.
///
#[cfg(feature = "awskms")]
pub fn load_seed(config: &dyn ServerConfig) -> Result<Vec<u8>, error::Error> {
    match config.kms_protection() {
        KmsProtection::Plaintext => Ok(config.seed()),
        KmsProtection::AwsKmsEnvelope(key_id) => {
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

#[cfg(feature = "gcpkms")]
mod gcpkms;

/// Load the seed value for the long-term key.
///
/// Loading behavior depends on the value of `config.kms_protection()`:
///
///  * If `config.kms_protection() == Plaintext` then the value returned from `config.seed()`
///    is used as-is and assumed to be a 32-byte hexadecimal value.
///
///  * Otherwise `config.seed()` is assumed to be an encrypted opaque blob generated from
///    a prior `EnvelopeEncryption::encrypt_seed` call. The value of `config.kms_protection()`
///    is parsed as a KMS key id and `EnvelopeEncryption::decrypt_seed` is called to obtain
///    the plaintext seed value.
///
#[cfg(feature = "gcpkms")]
pub fn load_seed(config: &dyn ServerConfig) -> Result<Vec<u8>, error::Error> {
    match config.kms_protection() {
        KmsProtection::Plaintext => Ok(config.seed()),
        KmsProtection::GoogleKmsEnvelope(resource_id) => {
            info!("Unwrapping seed via Google KMS key '{}'", resource_id);
            let kms = GcpKms::from_resource_id(resource_id)?;
            let seed = EnvelopeEncryption::decrypt_seed(&kms, &config.seed())?;
            Ok(seed)
        }
        _ => Err(error::Error::InvalidConfiguration(
            "AWS KMS not supported".to_string(),
        )),
    }
}

/// Load the seed value for the long-term key.
///
/// ## This build has KMS disabled
///
/// *The KMS feature is disabled in this build of Roughenough*.
///
/// The only supported `kms_protection` value in this build is `plaintext`. Any
/// other value will cause a runtime error.
///
///  * `config.seed()` is used as-is and assumed to be a 32-byte hexadecimal value
///
#[cfg(not(any(feature = "awskms", feature = "gcpkms")))]
pub fn load_seed(config: &dyn ServerConfig) -> Result<Vec<u8>, error::Error> {
    match config.kms_protection() {
        KmsProtection::Plaintext => Ok(config.seed()),
        v => Err(error::Error::InvalidConfiguration(format!(
            "kms_protection '{}' requires KMS, but server was not compiled with KMS support",
            v
        ))),
    }
}
