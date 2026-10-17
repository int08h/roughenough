use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
use {
    crate::seed::Seed,
    crate::storage::StorageError,
    aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey},
    aws_lc_rs::error::Unspecified,
    zeroize::Zeroizing,
};

#[cfg(any(feature = "longterm-aws", feature = "longterm-gcp"))]
use crate::storage::Protection;

// Debug is safe here: the ciphertexts and key id are not secret material
#[derive(Debug, Serialize, Deserialize)]
pub struct SeedEnvelope {
    /// Identifier of the KMS key used to encrypt the seed
    pub key_id: String,

    /// Seed encrypted by the data encryption key (DEK)
    #[serde(with = "base64")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub seed_ct: Vec<u8>,

    /// DEK encrypted by KMS
    #[serde(with = "base64")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dek_ct: Vec<u8>,
}

/// Bound into every envelope (KMS AAD or encryption context, and the local AES-GCM AAD);
/// changing it makes existing envelopes undecryptable
#[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) const AAD: &str = "roughenough-seed";

#[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
const DEK_LEN: usize = 32;

/// Data encryption key; always `DEK_LEN` bytes. Boxed so that moving it copies only a pointer
/// and leaves no key bytes behind outside the zeroized allocation.
#[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) type Dek = Zeroizing<Box<[u8]>>;

#[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) fn random_dek() -> Dek {
    let mut dek = Dek::new(Box::new([0u8; DEK_LEN]));
    aws_lc_rs::rand::fill(&mut dek).expect("should be infallible");
    dek
}

#[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) fn dek_from_plaintext(
    name: &'static str,
    plaintext: &[u8],
) -> Result<Dek, StorageError> {
    if plaintext.len() != DEK_LEN {
        return Err(StorageError::cloud(
            name,
            format!(
                "expected a {DEK_LEN}-byte DEK, response contained {} bytes",
                plaintext.len()
            ),
        ));
    }
    Ok(Dek::new(Box::from(plaintext)))
}

#[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) fn seal_seed(dek: &Dek, seed: &Seed) -> Result<Vec<u8>, Unspecified> {
    let key = RandomizedNonceKey::new(&AES_256_GCM, dek)?;

    // Sized up front so appending the tag and nonce never reallocates and leaves a
    // plaintext copy behind in freed memory
    let sealed_len = Seed::LEN + AES_256_GCM.tag_len() + AES_256_GCM.nonce_len();
    let mut in_out = Zeroizing::new(Vec::with_capacity(sealed_len));
    in_out.extend_from_slice(seed.expose());

    let nonce = key.seal_in_place_append_tag(Aad::from(AAD.as_bytes()), &mut *in_out)?;
    in_out.extend_from_slice(nonce.as_ref());

    // in_out is now (encrypted_seed || tag || nonce)
    assert_eq!(in_out.len(), sealed_len);
    Ok(std::mem::take(&mut *in_out))
}

#[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) fn open_seed(dek: &Dek, encrypted_seed: &[u8]) -> Result<Seed, Unspecified> {
    // encrypted_seed is (encrypted_seed || tag || nonce); reject anything too
    // short to contain all three parts instead of panicking on the arithmetic
    if encrypted_seed.len() < AES_256_GCM.tag_len() + AES_256_GCM.nonce_len() {
        return Err(Unspecified);
    }
    let ciphertext_len = encrypted_seed.len() - AES_256_GCM.nonce_len();

    let nonce = Nonce::try_assume_unique_for_key(&encrypted_seed[ciphertext_len..])?;
    let key = RandomizedNonceKey::new(&AES_256_GCM, dek)?;

    let mut in_out = Zeroizing::new(encrypted_seed[..ciphertext_len].to_vec());
    let plaintext = key.open_in_place(nonce, Aad::from(AAD.as_bytes()), &mut in_out)?;

    Seed::try_from(&plaintext[..]).map_err(|_| Unspecified)
}

/// Envelope-encrypt `seed` under a fresh DEK, which `seal_dek` encrypts with the KMS key
/// `key_id`.
#[cfg(any(feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) async fn encrypt_with(
    protection: Protection,
    key_id: &str,
    seed: &Seed,
    seal_dek: impl AsyncFnOnce(&Dek) -> Result<Vec<u8>, StorageError>,
) -> Result<SeedEnvelope, StorageError> {
    let dek = random_dek();
    let dek_ct = seal_dek(&dek).await?;
    let seed_ct = seal_seed(&dek, seed)
        .map_err(|_| StorageError::cloud(protection.name(), "local seed encryption failed"))?;

    Ok(SeedEnvelope {
        key_id: format!("{}{key_id}", protection.prefix()),
        dek_ct,
        seed_ct,
    })
}

/// Recover the seed in `envelope`; `open_dek` decrypts the DEK ciphertext with the KMS key
/// named by the envelope's key id (minus the scheme prefix).
#[cfg(any(feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) async fn decrypt_with(
    protection: Protection,
    envelope: &SeedEnvelope,
    open_dek: impl AsyncFnOnce(&str, &[u8]) -> Result<Dek, StorageError>,
) -> Result<Seed, StorageError> {
    let key_id = envelope
        .key_id
        .strip_prefix(protection.prefix())
        .ok_or_else(|| {
            StorageError::InvalidResource(format!(
                "key id '{}' lacks the '{}' prefix",
                envelope.key_id,
                protection.prefix()
            ))
        })?;

    let dek = open_dek(key_id, &envelope.dek_ct).await?;
    open_seed(&dek, &envelope.seed_ct).map_err(|_| {
        StorageError::cloud(
            protection.name(),
            "failed to decrypt seed (wrong key or corrupt envelope)",
        )
    })
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
    use aws_lc_rs::aead::{AES_256_GCM, Aad, RandomizedNonceKey};

    use super::*;

    fn test_dek(byte: u8) -> Dek {
        Dek::new(Box::new([byte; DEK_LEN]))
    }

    /// Seals `plaintext` the way `seal_seed` does, but with a caller-chosen AAD
    fn seal_with_aad(dek: &Dek, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let key = RandomizedNonceKey::new(&AES_256_GCM, dek).unwrap();
        let mut in_out = plaintext.to_vec();
        let nonce = key
            .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
            .unwrap();
        in_out.extend(nonce.as_ref());
        in_out
    }

    #[test]
    fn aad_bytes_are_pinned() {
        // Existing envelopes bind these exact bytes in KMS and in AES-GCM
        assert_eq!(AAD.as_bytes(), b"roughenough-seed");
    }

    #[test]
    fn open_seed_opens_a_previously_sealed_envelope() {
        // Sealed by an earlier release with DEK [0xd7; 32] and seed [0x5a; 32]
        let sealed = data_encoding::HEXLOWER
            .decode(
                b"466f3110669a8d5f7318d1c726b46ec49f41abc186842104a7ed101a5fc0c89a\
                  08cf9a88b7ef7f475bee19fe663952b09851dc0a37afcbde1a6a64cb",
            )
            .unwrap();

        let seed = open_seed(&test_dek(0xd7), &sealed).expect("old envelope must still open");
        assert_eq!(seed.expose(), &[0x5a; 32]);
    }

    #[test]
    fn seal_open_seed_roundtrip() {
        let original_seed = Seed::new_random();
        let dek = random_dek();

        let encrypted_seed = seal_seed(&dek, &original_seed).expect("seal should succeed");
        assert_eq!(
            encrypted_seed.len(),
            Seed::LEN + AES_256_GCM.tag_len() + AES_256_GCM.nonce_len()
        );
        assert_ne!(&encrypted_seed[..Seed::LEN], original_seed.expose());

        let decrypted_seed = open_seed(&dek, &encrypted_seed).expect("open should succeed");
        assert_eq!(decrypted_seed.expose(), original_seed.expose());
    }

    #[test]
    fn seal_open_seed_wrong_dek_fails() {
        let encrypted_seed = seal_seed(&test_dek(1), &Seed::new_random()).unwrap();
        let result = open_seed(&test_dek(2), &encrypted_seed);
        assert!(result.is_err());
    }

    #[test]
    fn open_seed_rejects_other_aad() {
        let dek = test_dek(0);
        let sealed = seal_with_aad(&dek, &[7u8; 32], b"wrong_aad");
        let result = open_seed(&dek, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn seal_open_seed_corrupted_data_fails() {
        let dek = test_dek(0);
        let mut encrypted_seed = seal_seed(&dek, &Seed::new_random()).unwrap();
        encrypted_seed[0] = encrypted_seed[0].wrapping_add(1);

        let result = open_seed(&dek, &encrypted_seed);
        assert!(result.is_err());
    }

    #[test]
    fn open_seed_too_short_input_fails() {
        // Shorter than tag + nonce: must error, not underflow
        let result = open_seed(&test_dek(0), &[0u8; 5]);
        assert!(result.is_err());

        let result = open_seed(&test_dek(0), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn open_seed_rejects_non_seed_length_plaintext() {
        let dek = test_dek(0);
        // Valid ciphertext under the right AAD, but not a 32-byte seed
        let sealed = seal_with_aad(&dek, &[0u8; 16], AAD.as_bytes());
        let result = open_seed(&dek, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn random_deks_differ() {
        assert_ne!(*random_dek(), *random_dek());
    }

    #[test]
    fn dek_from_plaintext_rejects_wrong_length() {
        for len in [0, 16, 31, 33] {
            assert!(matches!(
                dek_from_plaintext("test", &vec![0u8; len]),
                Err(StorageError::CloudBackend {
                    backend: "test",
                    ..
                })
            ));
        }
        assert_eq!(
            &**dek_from_plaintext("test", &[7u8; 32]).unwrap(),
            &[7u8; 32]
        );
    }

    #[test]
    fn envelope_serialization() {
        let envelope = SeedEnvelope {
            key_id: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/test".to_string(),
            dek_ct: vec![1, 2, 3, 4, 5],
            seed_ct: vec![6, 7, 8, 9, 10],
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: SeedEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(envelope.key_id, deserialized.key_id);
        assert_eq!(envelope.dek_ct, deserialized.dek_ct);
        assert_eq!(envelope.seed_ct, deserialized.seed_ct);
    }

    #[cfg(any(feature = "longterm-aws", feature = "longterm-gcp"))]
    mod cloud {
        use super::*;
        use crate::runtime::block_on;

        #[test]
        fn encrypt_decrypt_with_identity_kms_roundtrips() {
            let seed = Seed::new_random();

            // The "KMS" returns the DEK itself as its ciphertext
            let envelope = block_on(encrypt_with(
                Protection::AwsKms,
                "key-1",
                &seed,
                async |dek: &Dek| Ok(dek.to_vec()),
            ))
            .unwrap();
            assert_eq!(envelope.key_id, "aws-kms://key-1");
            assert_eq!(envelope.dek_ct.len(), DEK_LEN);

            let opened = block_on(decrypt_with(
                Protection::AwsKms,
                &envelope,
                async |key_id: &str, dek_ct: &[u8]| {
                    assert_eq!(key_id, "key-1");
                    dek_from_plaintext("test", dek_ct)
                },
            ))
            .unwrap();
            assert_eq!(opened.expose(), seed.expose());
        }

        #[test]
        fn decrypt_with_rejects_wrong_scheme_prefix() {
            for key_id in ["gcp-kms://wrong-cloud", "arn:aws:kms:us-east-1:1:key/x"] {
                let envelope = SeedEnvelope {
                    key_id: key_id.to_string(),
                    seed_ct: vec![1, 2, 3],
                    dek_ct: vec![4, 5, 6],
                };
                let result = block_on(decrypt_with(
                    Protection::AwsKms,
                    &envelope,
                    async |_: &str, _: &[u8]| -> Result<Dek, StorageError> {
                        panic!("KMS must not be called for a mismatched prefix")
                    },
                ));
                assert!(matches!(result, Err(StorageError::InvalidResource(_))));
            }
        }

        #[test]
        fn decrypt_with_reports_a_dek_that_does_not_open_the_seed() {
            let envelope = block_on(encrypt_with(
                Protection::GcpKms,
                "k",
                &Seed::new_random(),
                async |dek: &Dek| Ok(dek.to_vec()),
            ))
            .unwrap();

            let result = block_on(decrypt_with(
                Protection::GcpKms,
                &envelope,
                async |_: &str, _: &[u8]| Ok(test_dek(0)),
            ));
            assert!(matches!(
                result,
                Err(StorageError::CloudBackend {
                    backend: "GCP KMS",
                    ..
                })
            ));
        }
    }
}
