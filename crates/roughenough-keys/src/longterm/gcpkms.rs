use crate::longterm::envelope::{
    AAD, Dek, SeedEnvelope, decrypt_with, dek_from_plaintext, encrypt_with,
};
use crate::seed::Seed;
use crate::storage::{Protection, StorageError};

pub struct GcpKms {}

impl GcpKms {
    /// Envelope encrypts the `seed` using a random DEK and the KMS key `key_id`
    pub async fn encrypt_seed(key_id: &str, seed: &Seed) -> Result<SeedEnvelope, StorageError> {
        encrypt_with(Protection::GcpKms, key_id, seed, async |dek: &Dek| {
            Self::seal_dek(dek, key_id).await
        })
        .await
    }

    pub async fn decrypt_seed(envelope: &SeedEnvelope) -> Result<Seed, StorageError> {
        decrypt_with(Protection::GcpKms, envelope, Self::open_dek).await
    }

    async fn seal_dek(dek: &Dek, key_id: &str) -> Result<Vec<u8>, StorageError> {
        let client = google_cloud_kms_v1::client::KeyManagementService::builder()
            .with_tracing()
            .build()
            .await
            .map_err(|e| {
                StorageError::cloud(
                    Protection::GcpKms.name(),
                    format!("failed to create client: {e}"),
                )
            })?;

        let dek_crc32c = crc32c::crc32c(dek);

        // The SDK takes an owned buffer, so this copy of the DEK is not zeroized
        let dek_result = client
            .encrypt()
            .set_name(key_id)
            .set_plaintext(dek.to_vec())
            .set_plaintext_crc32c(dek_crc32c)
            .set_additional_authenticated_data(AAD.as_bytes())
            .send()
            .await
            .map_err(|e| {
                StorageError::cloud(Protection::GcpKms.name(), format!("encrypt failed: {e}"))
            })?;

        verify_crc32c(
            "ciphertext",
            dek_result.ciphertext_crc32c,
            &dek_result.ciphertext,
        )?;

        if !dek_result.name.starts_with(key_id) {
            return Err(StorageError::cloud(
                Protection::GcpKms.name(),
                format!(
                    "mismatched key ID in response: requested '{}', response used '{}'",
                    key_id, dek_result.name
                ),
            ));
        }

        if !dek_result.verified_plaintext_crc32c {
            return Err(StorageError::IntegrityCheckFailed(
                "GCP KMS did not verify the plaintext crc32c".to_string(),
            ));
        }

        Ok(dek_result.ciphertext.to_vec())
    }

    async fn open_dek(key_id: &str, dek_ciphertext: &[u8]) -> Result<Dek, StorageError> {
        let client = google_cloud_kms_v1::client::KeyManagementService::builder()
            .with_tracing()
            .build()
            .await
            .map_err(|e| {
                StorageError::cloud(
                    Protection::GcpKms.name(),
                    format!("failed to create client: {e}"),
                )
            })?;

        let ciphertext_crc32c = crc32c::crc32c(dek_ciphertext);

        let result = client
            .decrypt()
            .set_name(key_id)
            .set_ciphertext(dek_ciphertext.to_vec())
            .set_ciphertext_crc32c(ciphertext_crc32c)
            .set_additional_authenticated_data(AAD.as_bytes())
            .send()
            .await
            .map_err(|e| {
                StorageError::cloud(Protection::GcpKms.name(), format!("decrypt failed: {e}"))
            })?;

        verify_crc32c("plaintext", result.plaintext_crc32c, &result.plaintext)?;

        // The plaintext DEK in the SDK's response buffer is not zeroized; only our copy is
        dek_from_plaintext(Protection::GcpKms.name(), &result.plaintext)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::block_on;
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
    #[ignore = "requires GCP credentials"]
    fn encrypt_decrypt_seed_roundtrip() {
        // For GcpKms testing, use this key:
        let key_id = "projects/int08h-blog/locations/us-central1/keyRings/roughenough/cryptoKeys/roughenough-int08h";

        // Create a test seed
        let original_seed = Seed::new_random();

        // Encrypt the seed
        let envelope = block_on(GcpKms::encrypt_seed(key_id, &original_seed))
            .expect("encrypt_seed should succeed");

        // Verify the envelope contains the expected key ID
        assert!(envelope.key_id.starts_with(Protection::GcpKms.prefix()));
        assert!(envelope.key_id.contains(key_id));

        // Verify that encrypted data is present
        assert!(!envelope.dek_ct.is_empty());
        assert!(!envelope.seed_ct.is_empty());

        // Decrypt the seed
        let decrypted_seed =
            block_on(GcpKms::decrypt_seed(&envelope)).expect("decrypt_seed should succeed");

        // Verify the decrypted seed matches the original
        assert_eq!(decrypted_seed.expose(), original_seed.expose());
    }
}
