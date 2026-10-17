use aws_sdk_kms::error::DisplayErrorContext;
use aws_sdk_kms::primitives::Blob;

use crate::longterm::aws::sdk_config;
use crate::longterm::envelope::{
    AAD, Dek, SeedEnvelope, decrypt_with, dek_from_plaintext, encrypt_with,
};
use crate::seed::Seed;
use crate::storage::{Protection, StorageError};

pub struct AwsKms {}

impl AwsKms {
    pub async fn encrypt_seed(key_id: &str, seed: &Seed) -> Result<SeedEnvelope, StorageError> {
        encrypt_with(Protection::AwsKms, key_id, seed, async |dek: &Dek| {
            Self::seal_dek(dek, key_id).await
        })
        .await
    }

    pub async fn decrypt_seed(envelope: &SeedEnvelope) -> Result<Seed, StorageError> {
        decrypt_with(Protection::AwsKms, envelope, Self::open_dek).await
    }

    async fn seal_dek(dek: &Dek, key_id: &str) -> Result<Vec<u8>, StorageError> {
        let config = sdk_config(key_id).await?;
        let client = aws_sdk_kms::Client::new(&config);

        // The SDK copies the DEK into its own request buffer, which is not zeroized
        let response = client
            .encrypt()
            .key_id(key_id)
            .plaintext(Blob::from(&dek[..]))
            .encryption_context(AAD, AAD)
            .send()
            .await
            .map_err(|e| {
                StorageError::cloud(
                    Protection::AwsKms.name(),
                    format!("encrypt failed: {}", DisplayErrorContext(&e)),
                )
            })?;

        check_response_key_id(key_id, response.key_id())?;

        match response.ciphertext_blob() {
            Some(blob) => Ok(blob.as_ref().to_vec()),
            None => Err(StorageError::cloud(
                Protection::AwsKms.name(),
                "response did not include ciphertext",
            )),
        }
    }

    async fn open_dek(key_id: &str, dek_ciphertext: &[u8]) -> Result<Dek, StorageError> {
        let config = sdk_config(key_id).await?;
        let client = aws_sdk_kms::Client::new(&config);

        let response = client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::from(dek_ciphertext))
            .encryption_context(AAD, AAD)
            .send()
            .await
            .map_err(|e| {
                StorageError::cloud(
                    Protection::AwsKms.name(),
                    format!("decrypt failed: {}", DisplayErrorContext(&e)),
                )
            })?;

        check_response_key_id(key_id, response.key_id())?;

        // The plaintext DEK in the SDK's response buffer is not zeroized; only our copy is
        match response.plaintext() {
            Some(blob) => dek_from_plaintext(Protection::AwsKms.name(), blob.as_ref()),
            None => Err(StorageError::cloud(
                Protection::AwsKms.name(),
                "response did not include plaintext",
            )),
        }
    }
}

fn check_response_key_id(requested: &str, returned: Option<&str>) -> Result<(), StorageError> {
    match returned {
        Some(id) if id == requested => Ok(()),
        Some(id) => Err(StorageError::cloud(
            Protection::AwsKms.name(),
            format!("mismatched key ID in response: requested '{requested}', response used '{id}'"),
        )),
        None => Err(StorageError::cloud(
            Protection::AwsKms.name(),
            "response did not include a key ID",
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::longterm::awskms::{AwsKms, check_response_key_id};
    use crate::runtime::block_on;
    use crate::seed::Seed;
    use crate::storage::{Protection, StorageError};

    #[test]
    fn mismatched_response_key_id_is_an_error() {
        assert!(check_response_key_id("key-a", Some("key-a")).is_ok());
        assert!(matches!(
            check_response_key_id("key-a", Some("key-b")),
            Err(StorageError::CloudBackend { .. })
        ));
        assert!(matches!(
            check_response_key_id("key-a", None),
            Err(StorageError::CloudBackend { .. })
        ));
    }

    #[test]
    #[ignore = "requires AWS credentials"]
    fn encrypt_decrypt_seed_roundtrip() {
        // For AwsKms testing use this key:
        let key_id = "arn:aws:kms:us-east-2:382045063468:key/84e7ff78-7f16-4716-a300-a86c6efd6837";

        // Create a test seed
        let original_seed = Seed::new_random();

        // Encrypt the seed
        let envelope = block_on(AwsKms::encrypt_seed(key_id, &original_seed))
            .expect("encrypt_seed should succeed");

        // Verify the envelope contains the expected key ID
        assert!(envelope.key_id.starts_with(Protection::AwsKms.prefix()));
        assert!(envelope.key_id.contains(key_id));

        // Verify that encrypted data is present
        assert!(!envelope.dek_ct.is_empty());
        assert!(!envelope.seed_ct.is_empty());

        // Decrypt the seed
        let decrypted_seed =
            block_on(AwsKms::decrypt_seed(&envelope)).expect("decrypt_seed should succeed");

        // Verify the decrypted seed matches the original
        assert_eq!(decrypted_seed.expose(), original_seed.expose());
    }
}
