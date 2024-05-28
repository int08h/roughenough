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

use std::io::{Cursor, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

use crate::kms::{KmsError, KmsProvider, AD, DEK_LEN_BYTES, NONCE_LEN_BYTES, TAG_LEN_BYTES};
use crate::SEED_LENGTH;

const DEK_LEN_FIELD: usize = 2;
const NONCE_LEN_FIELD: usize = 2;

// 2 bytes - encrypted DEK length
// 2 bytes - nonce length
// n bytes - encrypted DEK
// n bytes - nonce
// n bytes - opaque (AEAD encrypted seed + tag)
const MIN_PAYLOAD_SIZE: usize = DEK_LEN_FIELD
    + NONCE_LEN_FIELD
    + DEK_LEN_BYTES
    + NONCE_LEN_BYTES
    + SEED_LENGTH as usize
    + TAG_LEN_BYTES;

// Convenience function to create zero-filled Vec of given size
fn vec_zero_filled(len: usize) -> Vec<u8> {
    (0..len).map(|_| 0).collect()
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
    pub fn decrypt_seed(
        kms: &dyn KmsProvider,
        ciphertext_blob: &[u8],
    ) -> Result<Vec<u8>, KmsError> {
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

        if nonce_len != NONCE_LEN_BYTES || dek_len > ciphertext_blob.len() {
            return Err(KmsError::InvalidData(format!(
                "invalid DEK ({}) or nonce ({}) length",
                dek_len, nonce_len
            )));
        }

        // Consume the wrapped DEK
        let mut encrypted_dek = vec_zero_filled(dek_len);
        tmp.read_exact(&mut encrypted_dek)?;

        // Consume the nonce
        let mut raw_nonce = [0u8; NONCE_LEN_BYTES];
        tmp.read_exact(&mut raw_nonce)?;
        let nonce = Nonce::assume_unique_for_key(raw_nonce);

        // Consume the encrypted seed + tag
        let mut encrypted_seed = Vec::new();
        tmp.read_to_end(&mut encrypted_seed)?;

        // Invoke KMS to decrypt the DEK
        let dek = kms.decrypt_dek(&encrypted_dek)?;

        // Decrypt the seed value using the DEK
        let unbound_dek = UnboundKey::new(&AES_256_GCM, &dek)?;
        let dek_opening_key = LessSafeKey::new(unbound_dek);
        match dek_opening_key.open_in_place(nonce, Aad::from(AD), &mut encrypted_seed) {
            Ok(plaintext) => Ok(plaintext.to_vec()),
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
    pub fn encrypt_seed(kms: &dyn KmsProvider, plaintext_seed: &[u8]) -> Result<Vec<u8>, KmsError> {
        // Generate random DEK and nonce
        let rng = SystemRandom::new();
        let mut raw_dek = [0u8; DEK_LEN_BYTES];
        let mut raw_nonce = [0u8; NONCE_LEN_BYTES];
        rng.fill(&mut raw_dek)?;
        rng.fill(&mut raw_nonce)?;

        // Ring will overwrite plaintext with ciphertext+tag in this buffer
        let mut buf = plaintext_seed.to_vec();

        // Encrypt the plaintext seed (in buf) using the DEK
        let nonce = Nonce::assume_unique_for_key(raw_nonce);
        let unbound_dek = UnboundKey::new(&AES_256_GCM, &raw_dek)?;
        let dek_seal_key = LessSafeKey::new(unbound_dek);

        // Output overwrites context of 'buf' and appends auth tag to 'buf'
        if let Err(_) = dek_seal_key.seal_in_place_append_tag(nonce, Aad::from(AD), &mut buf) {
            return Err(KmsError::OperationFailed(
                "failed to encrypt plaintext seed".to_string(),
            ));
        };

        // Use the KMS to wrap the DEK
        let wrapped_dek = kms.encrypt_dek(&raw_dek.to_vec())?;

        // And coalesce everything together
        let mut output = Vec::new();
        output.write_u16::<LittleEndian>(wrapped_dek.len() as u16)?;
        output.write_u16::<LittleEndian>(raw_nonce.len() as u16)?;
        output.write_all(&wrapped_dek)?;
        output.write_all(&raw_nonce)?;
        output.write_all(&buf)?;

        Ok(output)
    }
}

#[cfg(test)]
mod test {
    use crate::kms::envelope::{DEK_LEN_FIELD, MIN_PAYLOAD_SIZE, NONCE_LEN_FIELD};
    use crate::kms::EnvelopeEncryption;
    use crate::kms::{KmsError, KmsProvider};

    struct MockKmsProvider {}

    // Mock provider that returns a copy of the input
    impl KmsProvider for MockKmsProvider {
        fn encrypt_dek(&self, plaintext_dek: &Vec<u8>) -> Result<Vec<u8>, KmsError> {
            Ok(plaintext_dek.to_vec())
        }

        fn decrypt_dek(&self, encrypted_dek: &Vec<u8>) -> Result<Vec<u8>, KmsError> {
            Ok(encrypted_dek.to_vec())
        }
    }

    #[test]
    fn decryption_reject_input_too_short() {
        let ciphertext_blob = "1234567890";
        assert!(ciphertext_blob.len() < MIN_PAYLOAD_SIZE);

        let kms = MockKmsProvider {};
        let result = EnvelopeEncryption::decrypt_seed(&kms, ciphertext_blob.as_bytes());

        match result.expect_err("expected KmsError") {
            KmsError::InvalidData(msg) => assert!(msg.contains("ciphertext too short")),
            e => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let kms = MockKmsProvider {};
        let plaintext = Vec::from("This is the plaintext used for this test 1");

        let enc_result = EnvelopeEncryption::encrypt_seed(&kms, &plaintext);
        assert_eq!(enc_result.is_ok(), true);

        let ciphertext = enc_result.unwrap();
        assert_ne!(plaintext, ciphertext);

        let dec_result = EnvelopeEncryption::decrypt_seed(&kms, &ciphertext);
        assert_eq!(dec_result.is_ok(), true);

        let new_plaintext = dec_result.unwrap();
        assert_eq!(plaintext, new_plaintext);
    }

    #[test]
    fn invalid_dek_length_detected() {
        let kms = MockKmsProvider {};
        let plaintext = Vec::from("This is the plaintext used for this test 2");

        let enc_result = EnvelopeEncryption::encrypt_seed(&kms, &plaintext);
        assert_eq!(enc_result.is_ok(), true);

        let ciphertext = enc_result.unwrap();
        let mut ciphertext_copy = ciphertext.clone();

        ciphertext_copy[1] = 99;
        let dec_result = EnvelopeEncryption::decrypt_seed(&kms, &ciphertext_copy);
        match dec_result.expect_err("expected an error") {
            KmsError::InvalidData(msg) => assert!(msg.contains("invalid DEK")),
            e => panic!("unexpected error {:?}", e),
        }
    }

    #[test]
    fn invalid_nonce_length_detected() {
        let kms = MockKmsProvider {};
        let plaintext = Vec::from("This is the plaintext used for this test 3");

        let enc_result = EnvelopeEncryption::encrypt_seed(&kms, &plaintext);
        assert_eq!(enc_result.is_ok(), true);

        let ciphertext = enc_result.unwrap();
        let mut ciphertext_copy = ciphertext.clone();

        ciphertext_copy[2] = 1;
        let dec_result = EnvelopeEncryption::decrypt_seed(&kms, &ciphertext_copy);
        match dec_result.expect_err("expected an error") {
            KmsError::InvalidData(msg) => assert!(msg.contains("nonce (1)")),
            e => panic!("unexpected error {:?}", e),
        }
    }

    #[test]
    fn modified_ciphertext_is_detected() {
        let kms = MockKmsProvider {};
        let plaintext = Vec::from("This is the plaintext used for this test 4");

        let enc_result = EnvelopeEncryption::encrypt_seed(&kms, &plaintext);
        assert_eq!(enc_result.is_ok(), true);

        let ciphertext = enc_result.unwrap();
        assert_ne!(plaintext, ciphertext);

        // start corruption 4 bytes in, after the DEK and NONCE length fields
        for i in (DEK_LEN_FIELD + NONCE_LEN_FIELD)..ciphertext.len() {
            let mut ciphertext_copy = ciphertext.clone();
            // flip some bits
            ciphertext_copy[i] = ciphertext[i].wrapping_add(1);

            let dec_result = EnvelopeEncryption::decrypt_seed(&kms, &ciphertext_copy);

            match dec_result.expect_err("Expected a KmsError error here") {
                KmsError::OperationFailed(msg) => assert!(msg.contains("failed to decrypt")),
                e => panic!("unexpected result {:?}", e),
            }
        }
    }
}
