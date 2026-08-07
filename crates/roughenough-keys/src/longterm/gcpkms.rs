use roughenough_common::crypto::random_bytes;

use crate::longterm::envelope::{SeedEnvelope, open_seed, seal_seed};
use crate::seed::Seed;
use crate::storage::{Protection, StorageError};

pub struct GcpKms {}

impl GcpKms {
    const AAD: &'static [u8] = b"roughenough-seed";
    const BACKEND: &'static str = "GCP KMS";

    fn error(detail: impl Into<String>) -> StorageError {
        StorageError::CloudBackend {
            backend: Self::BACKEND,
            detail: detail.into(),
        }
    }

    /// Envelope encrypts the `seed` using a random DEK and the KMS key `key_id`
    pub async fn encrypt_seed(key_id: &str, seed: &Seed) -> Result<SeedEnvelope, StorageError> {
        let dek: [u8; 32] = random_bytes();

        let dek_ciphertext = Self::seal_dek(dek, key_id).await?;
        let seed_ciphertext = seal_seed(dek, seed, Self::AAD)
            .map_err(|_| Self::error("local seed encryption failed"))?;

        let mut kid = Protection::GcpKms.prefix().to_string();
        kid.push_str(key_id);

        Ok(SeedEnvelope {
            key_id: kid,
            dek_ct: dek_ciphertext,
            seed_ct: seed_ciphertext,
        })
    }

    pub async fn decrypt_seed(envelope: &SeedEnvelope) -> Result<Seed, StorageError> {
        let key_id = strip_key_prefix(&envelope.key_id)?;

        // Decrypt the DEK using GCP KMS, then use the DEK to decrypt the seed
        let dek = Self::open_dek(&envelope.dek_ct, key_id).await?;
        open_seed(dek, &envelope.seed_ct, Self::AAD)
            .map_err(|_| Self::error("failed to decrypt seed (wrong key or corrupt envelope)"))
    }

    async fn seal_dek(dek: [u8; 32], key_id: &str) -> Result<Vec<u8>, StorageError> {
        let client = google_cloud_kms_v1::client::KeyManagementService::builder()
            .with_tracing()
            .build()
            .await
            .map_err(|e| Self::error(format!("failed to create client: {e}")))?;

        let dek_crc32c = crc32c::crc32c(&dek);

        let dek_result = client
            .encrypt()
            .set_name(key_id)
            .set_plaintext(dek.to_vec())
            .set_plaintext_crc32c(dek_crc32c)
            .set_additional_authenticated_data(Self::AAD)
            .send()
            .await
            .map_err(|e| Self::error(format!("encrypt failed: {e}")))?;

        verify_crc32c(
            "ciphertext",
            dek_result.ciphertext_crc32c,
            &dek_result.ciphertext,
        )?;

        if !dek_result.name.starts_with(key_id) {
            return Err(Self::error(format!(
                "mismatched key ID in response: requested '{}', response used '{}'",
                key_id, dek_result.name
            )));
        }

        if !dek_result.verified_plaintext_crc32c {
            return Err(StorageError::IntegrityCheckFailed(
                "GCP KMS did not verify the plaintext crc32c".to_string(),
            ));
        }

        Ok(dek_result.ciphertext.to_vec())
    }

    async fn open_dek(dek_ciphertext: &[u8], key_id: &str) -> Result<[u8; 32], StorageError> {
        let client = google_cloud_kms_v1::client::KeyManagementService::builder()
            .with_tracing()
            .build()
            .await
            .map_err(|e| Self::error(format!("failed to create client: {e}")))?;

        let ciphertext_crc32c = crc32c::crc32c(dek_ciphertext);

        let result = client
            .decrypt()
            .set_name(key_id)
            .set_ciphertext(dek_ciphertext.to_vec())
            .set_ciphertext_crc32c(ciphertext_crc32c)
            .set_additional_authenticated_data(Self::AAD)
            .send()
            .await
            .map_err(|e| Self::error(format!("decrypt failed: {e}")))?;

        verify_crc32c("plaintext", result.plaintext_crc32c, &result.plaintext)?;

        dek_from_plaintext(&result.plaintext)
    }
}

fn strip_key_prefix(key_id: &str) -> Result<&str, StorageError> {
    let prefix = Protection::GcpKms.prefix();
    key_id.strip_prefix(prefix).ok_or_else(|| {
        StorageError::InvalidResource(format!("key id '{key_id}' lacks the '{prefix}' prefix"))
    })
}

fn verify_crc32c(label: &str, expected: Option<i64>, data: &[u8]) -> Result<(), StorageError> {
    let computed = crc32c::crc32c(data) as i64;
    match expected {
        Some(expected) if expected == computed => Ok(()),
        Some(expected) => Err(StorageError::IntegrityCheckFailed(format!(
            "GCP KMS {label} crc32c mismatch: response says {expected:#x}, computed {computed:#x}"
        ))),
        None => Err(StorageError::IntegrityCheckFailed(format!(
            "GCP KMS response omitted the {label} crc32c"
        ))),
    }
}

fn dek_from_plaintext(plaintext: &[u8]) -> Result<[u8; 32], StorageError> {
    plaintext.try_into().map_err(|_| {
        GcpKms::error(format!(
            "expected a 32-byte DEK, response contained {} bytes",
            plaintext.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Seed;

    #[test]
    fn crc32c_mismatch_is_an_error_not_a_panic() {
        let data = b"some response bytes";
        let good = crc32c::crc32c(data) as i64;

        assert!(verify_crc32c("ciphertext", Some(good), data).is_ok());

        let result = verify_crc32c("ciphertext", Some(good + 1), data);
        assert!(matches!(result, Err(StorageError::IntegrityCheckFailed(_))));
    }

    #[test]
    fn missing_crc32c_is_an_error() {
        let result = verify_crc32c("plaintext", None, b"anything");
        assert!(matches!(result, Err(StorageError::IntegrityCheckFailed(_))));
    }

    #[test]
    fn bad_key_prefix_is_an_error_not_a_panic() {
        assert!(matches!(
            strip_key_prefix("aws-kms://wrong-cloud"),
            Err(StorageError::InvalidResource(_))
        ));

        let good = format!(
            "{}projects/p/locations/l/keyRings/r/cryptoKeys/k",
            Protection::GcpKms.prefix()
        );
        assert_eq!(
            strip_key_prefix(&good).unwrap(),
            "projects/p/locations/l/keyRings/r/cryptoKeys/k"
        );
    }

    #[test]
    fn wrong_length_dek_is_an_error_not_a_panic() {
        assert!(matches!(
            dek_from_plaintext(&[0u8; 31]),
            Err(StorageError::CloudBackend { .. })
        ));
        assert_eq!(dek_from_plaintext(&[9u8; 32]).unwrap(), [9u8; 32]);
    }

    #[tokio::test]
    #[ignore = "requires GCP credentials"]
    async fn encrypt_decrypt_seed_roundtrip() {
        // For GcpKms testing, use this key:
        let key_id = "projects/int08h-blog/locations/us-central1/keyRings/roughenough/cryptoKeys/roughenough-int08h";

        // Create a test seed
        let original_seed = Seed::new_random();
        let original_bytes = original_seed.expose().to_vec();

        // Encrypt the seed
        let envelope = GcpKms::encrypt_seed(key_id, &original_seed)
            .await
            .expect("encrypt_seed should succeed");

        // Verify the envelope contains the expected key ID
        assert!(envelope.key_id.starts_with(Protection::GcpKms.prefix()));
        assert!(envelope.key_id.contains(key_id));

        // Verify that encrypted data is present
        assert!(!envelope.dek_ct.is_empty());
        assert!(!envelope.seed_ct.is_empty());

        // Decrypt the seed
        let decrypted_seed = GcpKms::decrypt_seed(&envelope)
            .await
            .expect("decrypt_seed should succeed");

        // Verify the decrypted seed matches the original
        assert_eq!(decrypted_seed.expose(), &original_bytes);
    }

    #[test]
    fn envelope_serialization() {
        use serde_json;

        let envelope = SeedEnvelope {
            key_id: "gcp-kms://projects/test/locations/global/keyRings/test/cryptoKeys/test"
                .to_string(),
            dek_ct: vec![1, 2, 3, 4, 5],
            seed_ct: vec![6, 7, 8, 9, 10],
        };

        // Serialize to JSON
        let json = serde_json::to_string(&envelope).unwrap();

        // Deserialize back
        let deserialized: SeedEnvelope = serde_json::from_str(&json).unwrap();

        // Verify
        assert_eq!(envelope.key_id, deserialized.key_id);
        assert_eq!(envelope.dek_ct, deserialized.dek_ct);
        assert_eq!(envelope.seed_ct, deserialized.seed_ct);
    }
}
