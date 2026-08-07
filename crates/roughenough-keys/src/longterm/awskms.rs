use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::error::DisplayErrorContext;
use aws_sdk_kms::primitives::Blob;
use roughenough_common::crypto::random_bytes;

use crate::longterm::envelope::{SeedEnvelope, open_seed, seal_seed};
use crate::seed::Seed;
use crate::storage::{Protection, StorageError};

pub struct AwsKms {}

impl AwsKms {
    const AAD: &'static str = "roughenough-seed";
    const BACKEND: &'static str = "AWS KMS";

    fn error(detail: impl Into<String>) -> StorageError {
        StorageError::CloudBackend {
            backend: Self::BACKEND,
            detail: detail.into(),
        }
    }

    pub async fn encrypt_seed(key_id: &str, seed: &Seed) -> Result<SeedEnvelope, StorageError> {
        let dek: [u8; 32] = random_bytes();

        let dek_ciphertext = Self::seal_dek(dek, key_id).await?;
        let seed_ciphertext = seal_seed(dek, seed, Self::AAD.as_ref())
            .map_err(|_| Self::error("local seed encryption failed"))?;

        let mut kid = Protection::AwsKms.prefix().to_string();
        kid.push_str(key_id);

        Ok(SeedEnvelope {
            key_id: kid,
            dek_ct: dek_ciphertext,
            seed_ct: seed_ciphertext,
        })
    }

    pub async fn decrypt_seed(envelope: &SeedEnvelope) -> Result<Seed, StorageError> {
        let key_id = strip_key_prefix(&envelope.key_id)?;

        // Decrypt the DEK using AWS KMS, then use the DEK to decrypt the seed
        let dek = Self::open_dek(&envelope.dek_ct, key_id).await?;
        open_seed(dek, &envelope.seed_ct, Self::AAD.as_ref())
            .map_err(|_| Self::error("failed to decrypt seed (wrong key or corrupt envelope)"))
    }

    async fn seal_dek(dek: [u8; 32], key_id: &str) -> Result<Vec<u8>, StorageError> {
        let region = extract_aws_region(key_id)?;

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .load()
            .await;

        let client = aws_sdk_kms::Client::new(&config);
        let response = client
            .encrypt()
            .key_id(key_id)
            .plaintext(Blob::from(dek.as_slice()))
            .encryption_context(Self::AAD, Self::AAD)
            .send()
            .await
            .map_err(|e| Self::error(format!("encrypt failed: {}", DisplayErrorContext(&e))))?;

        check_response_key_id(key_id, response.key_id())?;

        match response.ciphertext_blob() {
            Some(blob) => Ok(blob.as_ref().to_vec()),
            None => Err(Self::error("response did not include ciphertext")),
        }
    }

    async fn open_dek(dek_ciphertext: &[u8], key_id: &str) -> Result<[u8; 32], StorageError> {
        let region = extract_aws_region(key_id)?;

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .load()
            .await;

        let client = aws_sdk_kms::Client::new(&config);
        let response = client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::from(dek_ciphertext))
            .encryption_context(Self::AAD, Self::AAD)
            .send()
            .await
            .map_err(|e| Self::error(format!("decrypt failed: {}", DisplayErrorContext(&e))))?;

        check_response_key_id(key_id, response.key_id())?;

        match response.plaintext() {
            Some(blob) => dek_from_plaintext(blob.as_ref()),
            None => Err(Self::error("response did not include plaintext")),
        }
    }
}

fn strip_key_prefix(key_id: &str) -> Result<&str, StorageError> {
    let prefix = Protection::AwsKms.prefix();
    key_id.strip_prefix(prefix).ok_or_else(|| {
        StorageError::InvalidResource(format!("key id '{key_id}' lacks the '{prefix}' prefix"))
    })
}

fn check_response_key_id(requested: &str, returned: Option<&str>) -> Result<(), StorageError> {
    match returned {
        Some(id) if id == requested => Ok(()),
        Some(id) => Err(AwsKms::error(format!(
            "mismatched key ID in response: requested '{requested}', response used '{id}'"
        ))),
        None => Err(AwsKms::error("response did not include a key ID")),
    }
}

fn dek_from_plaintext(plaintext: &[u8]) -> Result<[u8; 32], StorageError> {
    plaintext.try_into().map_err(|_| {
        AwsKms::error(format!(
            "expected a 32-byte DEK, response contained {} bytes",
            plaintext.len()
        ))
    })
}

fn extract_aws_region(arn: &str) -> Result<String, StorageError> {
    // "arn:aws:secretsmanager:us-east-2:382045063468:secret:roughenough-seed-QtQH5f";
    //                        ^
    match arn.split(':').nth(3) {
        Some(region) if !region.is_empty() => Ok(region.to_string()),
        _ => Err(StorageError::InvalidResource(format!(
            "cannot determine AWS region from '{arn}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use crate::longterm::awskms::{
        AwsKms, check_response_key_id, dek_from_plaintext, extract_aws_region, strip_key_prefix,
    };
    use crate::longterm::envelope::SeedEnvelope;
    use crate::seed::Seed;
    use crate::storage::{Protection, StorageError};

    #[test]
    fn region_is_extracted_from_arn() {
        let arn1 = "arn:aws:secretsmanager:us-east-2:382045063468:secret:roughenough-foo-12345";
        assert_eq!(extract_aws_region(arn1).unwrap(), "us-east-2");

        let arn2 = "arn:aws:kms:us-east-1:382045063468:key/84e7ff78-7f16-4716-a300-12345678abcd";
        assert_eq!(extract_aws_region(arn2).unwrap(), "us-east-1");
    }

    #[test]
    fn malformed_arn_is_an_error_not_a_panic() {
        assert!(matches!(
            extract_aws_region("not-an-arn"),
            Err(StorageError::InvalidResource(_))
        ));
        assert!(matches!(
            extract_aws_region("arn:aws:kms"),
            Err(StorageError::InvalidResource(_))
        ));
        assert!(matches!(
            extract_aws_region("arn:aws:kms::empty-region"),
            Err(StorageError::InvalidResource(_))
        ));
        assert!(matches!(
            extract_aws_region(""),
            Err(StorageError::InvalidResource(_))
        ));
    }

    #[test]
    fn bad_key_prefix_is_an_error_not_a_panic() {
        assert!(matches!(
            strip_key_prefix("gcp-kms://wrong-cloud"),
            Err(StorageError::InvalidResource(_))
        ));
        assert!(matches!(
            strip_key_prefix("arn:aws:kms:us-east-1:1:key/x"),
            Err(StorageError::InvalidResource(_))
        ));

        let good = format!(
            "{}arn:aws:kms:us-east-1:1:key/x",
            Protection::AwsKms.prefix()
        );
        assert_eq!(
            strip_key_prefix(&good).unwrap(),
            "arn:aws:kms:us-east-1:1:key/x"
        );
    }

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
    fn wrong_length_dek_is_an_error_not_a_panic() {
        assert!(matches!(
            dek_from_plaintext(&[0u8; 16]),
            Err(StorageError::CloudBackend { .. })
        ));
        assert!(matches!(
            dek_from_plaintext(&[0u8; 33]),
            Err(StorageError::CloudBackend { .. })
        ));
        assert_eq!(dek_from_plaintext(&[7u8; 32]).unwrap(), [7u8; 32]);
    }

    #[tokio::test]
    #[ignore = "requires AWS credentials"]
    async fn encrypt_decrypt_seed_roundtrip() {
        // For AwsKms testing use this key:
        let key_id = "arn:aws:kms:us-east-2:382045063468:key/84e7ff78-7f16-4716-a300-a86c6efd6837";

        // Create a test seed
        let original_seed = Seed::new_random();
        let original_bytes = original_seed.expose().to_vec();

        // Encrypt the seed
        let envelope = AwsKms::encrypt_seed(key_id, &original_seed)
            .await
            .expect("encrypt_seed should succeed");

        // Verify the envelope contains the expected key ID
        assert!(envelope.key_id.starts_with(Protection::AwsKms.prefix()));
        assert!(envelope.key_id.contains(key_id));

        // Verify that encrypted data is present
        assert!(!envelope.dek_ct.is_empty());
        assert!(!envelope.seed_ct.is_empty());

        // Decrypt the seed
        let decrypted_seed = AwsKms::decrypt_seed(&envelope)
            .await
            .expect("decrypt_seed should succeed");

        // Verify the decrypted seed matches the original
        assert_eq!(decrypted_seed.expose(), &original_bytes);
    }

    #[test]
    fn envelope_serialization() {
        use serde_json;

        let envelope = SeedEnvelope {
            key_id: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/test".to_string(),
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
