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

extern crate hex;

use std::io::{Cursor, Read, Write};
use std::str::FromStr;

use ring::aead::{open_in_place, seal_in_place, OpeningKey, SealingKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

use super::super::MIN_SEED_LENGTH;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use kms::{KmsError, KmsProvider, AD, DEK_SIZE_BYTES, NONCE_SIZE_BYTES, TAG_SIZE_BYTES};

const DEK_LEN_FIELD: usize = 2;
const NONCE_LEN_FIELD: usize = 2;

// 2 bytes - encrypted DEK length
// 2 bytes - nonce length
// n bytes - encrypted DEK
// n bytes - nonce
// n bytes - opaque (AEAD encrypted seed + tag)
const MIN_PAYLOAD_SIZE: usize = DEK_LEN_FIELD
    + NONCE_LEN_FIELD
    + DEK_SIZE_BYTES
    + NONCE_SIZE_BYTES
    + MIN_SEED_LENGTH as usize
    + TAG_SIZE_BYTES;

// No input prefix to skip, consume entire buffer
const IN_PREFIX_LEN: usize = 0;

// Convenience function to create zero-filled Vec of given size
fn vec_zero_filled(len: usize) -> Vec<u8> {
    (0..len).into_iter().map(|_| 0).collect()
}

/// Envelope encryption of the long-term key seed value.
///
/// The seed is encrypted using AES-GCM-256 with:
///
///   * 32 byte (256 bit) random key
///   * 12 byte (96 bit) random nonce
///   * 16 byte (128 bit) authentication tag
///
/// Randomness obtained from
/// [`ring::rand::SecureRandom`](https://briansmith.org/rustdoc/ring/rand/trait.SecureRandom.html).
///
/// The key used to encrypt the seed is wrapped (encrypted) using a
/// [`KmsProvider`](trait.KmsProvider.html) implementation.
///
pub struct EnvelopeEncryption;

impl EnvelopeEncryption {
    /// Decrypt a seed previously encrypted with `encrypt_seed()`
    pub fn decrypt_seed(kms: &KmsProvider, ciphertext_blob: &[u8]) -> Result<Vec<u8>, KmsError> {
        if ciphertext_blob.len() < MIN_PAYLOAD_SIZE {
            return Err(KmsError::InvalidData(format!(
                "ciphertext too short: min {}, found {}",
                MIN_PAYLOAD_SIZE,
                ciphertext_blob.len()
            )));
        }

        let mut tmp = Cursor::new(ciphertext_blob);

        // Read the lengths of the wrapped DEK and of the nonce
        let dek_len = tmp.read_u16::<LittleEndian>()? as usize;
        let nonce_len = tmp.read_u16::<LittleEndian>()? as usize;

        if dek_len != DEK_SIZE_BYTES || nonce_len != NONCE_SIZE_BYTES {
            return Err(KmsError::InvalidData(format!(
                "invalid DEK ({}) or nonce ({}) length",
                dek_len, nonce_len
            )));
        }

        // Consume the wrapped DEK
        let mut encrypted_dek = vec_zero_filled(dek_len);
        tmp.read_exact(&mut encrypted_dek)?;

        // Consume the nonce
        let mut nonce = vec_zero_filled(nonce_len);
        tmp.read_exact(&mut nonce)?;

        // Consume the encrypted seed + tag
        let mut encrypted_seed = Vec::new();
        tmp.read_to_end(&mut encrypted_seed)?;

        // Invoke KMS to decrypt the DEK
        let dek = kms.decrypt_dek(&encrypted_dek)?;

        // Decrypt the seed value using the DEK
        let dek_open_key = OpeningKey::new(&AES_256_GCM, &dek)?;
        match open_in_place(
            &dek_open_key,
            &nonce,
            AD.as_bytes(),
            IN_PREFIX_LEN,
            &mut encrypted_seed,
        ) {
            Ok(plaintext_seed) => Ok(plaintext_seed.to_vec()),
            Err(_) => Err(KmsError::OperationFailed(
                "failed to decrypt plaintext seed".to_string(),
            )),
        }
    }

    ///
    /// Encrypt the seed value and protect the seed's encryption key using a
    /// [`KmsProvider`](trait.KmsProvider.html).
    ///
    /// The returned encrypted byte blob is safe to store on unsecured media.
    ///
    pub fn encrypt_seed(kms: &KmsProvider, plaintext_seed: &[u8]) -> Result<Vec<u8>, KmsError> {
        // Generate random DEK and nonce
        let rng = rand::SystemRandom::new();
        let mut dek = [0u8; DEK_SIZE_BYTES];
        let mut nonce = [0u8; NONCE_SIZE_BYTES];
        rng.fill(&mut dek)?;
        rng.fill(&mut nonce)?;

        // Ring will overwrite plaintext with ciphertext in this buffer
        let mut plaintext_buf = plaintext_seed.to_vec();

        // Reserve space for the authentication tag which will be appended after the ciphertext
        plaintext_buf.reserve(TAG_SIZE_BYTES);
        for _ in 0..TAG_SIZE_BYTES {
            plaintext_buf.push(0);
        }

        // Encrypt the plaintext seed using the DEK
        let dek_seal_key = SealingKey::new(&AES_256_GCM, &dek)?;
        let encrypted_seed = match seal_in_place(
            &dek_seal_key,
            &nonce,
            AD.as_bytes(),
            &mut plaintext_buf,
            TAG_SIZE_BYTES,
        ) {
            Ok(enc_len) => plaintext_buf[..enc_len].to_vec(),
            Err(_) => {
                return Err(KmsError::OperationFailed(
                    "failed to encrypt plaintext seed".to_string(),
                ))
            }
        };

        // Use the KMS to wrap the DEK
        let wrapped_dek = kms.encrypt_dek(&dek.to_vec())?;

        // And coalesce everything together
        let mut output = Vec::new();
        output.write_u16::<LittleEndian>(wrapped_dek.len() as u16)?;
        output.write_u16::<LittleEndian>(nonce.len() as u16)?;
        output.write_all(&wrapped_dek)?;
        output.write_all(&nonce)?;
        output.write_all(&encrypted_seed)?;

        Ok(output)
    }
}
