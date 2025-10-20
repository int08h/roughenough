use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::primitives::Blob;
use roughenough_common::crypto::random_bytes;

use crate::longterm::envelope::{SeedEnvelope, open_seed, seal_seed};
use crate::seed::Seed;
use crate::storage::Protection;

pub struct AwsKms {}

impl AwsKms {
    const AAD: &'static str = "roughenough-seed";

    pub async fn encrypt_seed(key_id: &str, seed: &Seed) -> SeedEnvelope {
        let dek: [u8; 32] = random_bytes();

        let dek_ciphertext = Self::seal_dek(dek, key_id).await;
        let seed_ciphertext = seal_seed(dek, seed, Self::AAD.as_ref());

        let mut kid = Protection::AwsKms.prefix().to_string();
        kid.push_str(key_id);

        SeedEnvelope {
            key_id: kid,
            dek_ct: dek_ciphertext,
            seed_ct: seed_ciphertext,
        }
    }

    pub async fn decrypt_seed(envelope: &SeedEnvelope) -> Seed {
        // Extract the AWS KMS key ID from the envelope
        let key_id = envelope
            .key_id
            .strip_prefix(Protection::AwsKms.prefix())
            .unwrap_or_else(|| panic!("invalid AWS KMS key ID prefix: {}", envelope.key_id));

        // Decrypt the DEK using AWS KMS
        let dek = Self::open_dek(&envelope.dek_ct, key_id).await;

        // Use the DEK to decrypt the seed
        open_seed(dek, &envelope.seed_ct, Self::AAD.as_ref()).expect("failed to decrypt seed")
    }

    async fn seal_dek(dek: [u8; 32], key_id: &str) -> Vec<u8> {
        let region = extract_aws_region(key_id);

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
            .expect("call to AWS KMS failed");

        assert_eq!(
            key_id,
            response.key_id().unwrap(),
            "mismatched key ID in AWS response"
        );

        let ciphertext = response
            .ciphertext_blob()
            .expect("AWS KMS did not return ciphertext")
            .as_ref();

        ciphertext.to_vec()
    }

    async fn open_dek(dek_ciphertext: &[u8], key_id: &str) -> [u8; 32] {
        let region = extract_aws_region(key_id);

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
            .expect("call to AWS KMS decrypt failed");

        assert_eq!(
            key_id,
            response.key_id().unwrap(),
            "mismatched key ID in AWS decrypt response"
        );

        let plaintext = response
            .plaintext()
            .expect("AWS KMS did not return plaintext")
            .as_ref();

        let mut dek = [0u8; 32];
        dek.copy_from_slice(plaintext);
        dek
    }
}

fn extract_aws_region(arn: &str) -> String {
    // "arn:aws:secretsmanager:us-east-2:382045063468:secret:roughenough-seed-QtQH5f";
    //                        ^
    arn.split(":").nth(3).unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use crate::longterm::awskms::{AwsKms, extract_aws_region};
    use crate::longterm::envelope::SeedEnvelope;
    use crate::seed::Seed;
    use crate::storage::Protection;

    #[test]
    fn region_is_extracted_from_arn() {
        let arn1 = "arn:aws:secretsmanager:us-east-2:382045063468:secret:roughenough-foo-12345";
        assert_eq!(extract_aws_region(arn1), "us-east-2");

        let arn2 = "arn:aws:kms:us-east-1:382045063468:key/84e7ff78-7f16-4716-a300-12345678abcd";
        assert_eq!(extract_aws_region(arn2), "us-east-1");
    }

    #[cfg(feature = "longterm-aws-kms")]
    #[tokio::test]
    #[ignore = "requires AWS credentials"]
    async fn encrypt_decrypt_seed_roundtrip() {
        // For AwsKms testing use this key:
        let key_id = "arn:aws:kms:us-east-2:382045063468:key/84e7ff78-7f16-4716-a300-a86c6efd6837";

        // Create a test seed
        let original_seed = Seed::new_random();
        let original_bytes = original_seed.expose().to_vec();

        // Encrypt the seed
        let envelope = AwsKms::encrypt_seed(key_id, &original_seed).await;

        // Verify the envelope contains the expected key ID
        assert!(envelope.key_id.starts_with(Protection::AwsKms.prefix()));
        assert!(envelope.key_id.contains(key_id));

        // Verify that encrypted data is present
        assert!(!envelope.dek_ct.is_empty());
        assert!(!envelope.seed_ct.is_empty());

        // Decrypt the seed
        let decrypted_seed = AwsKms::decrypt_seed(&envelope).await;

        // Verify the decrypted seed matches the original
        assert_eq!(decrypted_seed.expose(), &original_bytes);
    }

    #[cfg(feature = "longterm-aws-kms")]
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
