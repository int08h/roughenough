use aws_lc_rs::aead::nonce_sequence::Counter32Builder;
use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey};
use aws_lc_rs::error::Unspecified;
use serde::{Deserialize, Serialize};

use crate::seed::Seed;

#[derive(Serialize, Deserialize)]
pub struct SeedEnvelope {
    /// Identifier of the KMS key used to encrypt the seed
    pub key_id: String,

    /// Seed encrypted by the data encryption key (DEK)
    #[serde(with = "base64")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub seed_ct: Vec<u8>,

    /// DEK encrypted by KMS
    #[serde(with = "base64")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dek_ct: Vec<u8>,
}

#[allow(dead_code)] // uses are behind cargo features
pub(crate) fn seal_seed(dek: [u8; 32], seed: &Seed, aad: &[u8]) -> Vec<u8> {
    assert!(aad.len() < 1024, "AAD must be less than 1024 bytes");

    let unbound_key = UnboundKey::new(&AES_256_GCM_SIV, &dek).unwrap();
    let nonce_sequence = Counter32Builder::new().build();
    let mut seal_key = SealingKey::new(unbound_key, nonce_sequence);

    let mut in_out = seed.expose().to_vec();
    seal_key
        .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
        .unwrap();

    in_out
}

#[allow(dead_code)] // uses are behind cargo features
pub(crate) fn open_seed(
    dek: [u8; 32],
    encrypted_seed: &[u8],
    aad: &[u8],
) -> Result<Seed, Unspecified> {
    assert!(aad.len() < 1024, "AAD must be less than 1024 bytes");

    let unbound_key = UnboundKey::new(&AES_256_GCM_SIV, &dek)?;
    let nonce_sequence = Counter32Builder::new().build();
    let mut open_key = OpeningKey::new(unbound_key, nonce_sequence);

    let mut in_out = encrypted_seed.to_vec();
    let plaintext = open_key.open_in_place(Aad::from(aad), &mut in_out)?;
    let seed = Seed::new(plaintext);

    Ok(seed)
}

/// Serialize strings to/from base64 for serde.
mod base64 {
    use data_encoding::BASE64_NOPAD;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_NOPAD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_NOPAD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use crate::longterm::envelope::{open_seed, seal_seed};
    use crate::seed::Seed;

    #[test]
    fn seal_open_seed_roundtrip() {
        let original_seed_data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let original_seed = Seed::new(&original_seed_data);

        let dek = [
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
            0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc,
            0xbd, 0xbe, 0xbf, 0xc0,
        ];

        // Create test AAD (Additional Authenticated Data)
        let aad = b"test_aad_data";

        // Seal the seed
        let encrypted_seed = seal_seed(dek, &original_seed, aad);

        // Verify that the encrypted data is different from the original
        assert_ne!(encrypted_seed, original_seed_data);

        // Verify that the encrypted data is longer (due to authentication tag)
        assert!(encrypted_seed.len() > original_seed_data.len());

        // Open (decrypt) the seed
        let decrypted_seed = open_seed(dek, &encrypted_seed, aad).expect("Failed to decrypt seed");

        // Verify that the decrypted seed matches the original
        assert_eq!(decrypted_seed.expose(), original_seed.expose());
    }

    #[test]
    fn seal_open_seed_wrong_aad_fails() {
        // Test that decryption fails with wrong AAD
        let original_seed = Seed::new_random();
        let dek = [0u8; 32];
        let correct_aad = b"correct_aad";
        let wrong_aad = b"wrong_aad";

        let encrypted_seed = seal_seed(dek, &original_seed, correct_aad);

        // Attempting to decrypt with wrong AAD should fail
        let result = open_seed(dek, &encrypted_seed, wrong_aad);
        assert!(result.is_err(), "Decryption should fail with wrong AAD");
    }

    #[test]
    fn seal_open_seed_corrupted_data_fails() {
        // Test that decryption fails with corrupted encrypted data
        let original_seed = Seed::new_random();
        let dek = [0u8; 32];
        let aad = b"test_aad";

        let mut encrypted_seed = seal_seed(dek, &original_seed, aad);

        // Corrupt the encrypted data
        if let Some(byte) = encrypted_seed.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }

        // Attempting to decrypt corrupted data should fail
        let result = open_seed(dek, &encrypted_seed, aad);
        assert!(
            result.is_err(),
            "Decryption should fail with corrupted data"
        );
    }
}
