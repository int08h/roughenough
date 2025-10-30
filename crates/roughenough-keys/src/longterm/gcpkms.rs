use roughenough_common::crypto::random_bytes;

use crate::longterm::envelope::{SecretEnvelope, open_secret, seal_secret};
use crate::seed::Secret;
use crate::storage::Protection;

pub struct GcpKms {}

impl GcpKms {
    const AAD: &'static [u8] = b"roughenough-secret";

    /// Envelope encrypts the `seed` using a random DEK and the KMS key `key_id`
    pub async fn encrypt_secret(key_id: &str, secret: &Secret) -> SecretEnvelope {
        let dek: [u8; 32] = random_bytes();

        let dek_ciphertext = Self::seal_dek(dek, key_id).await;
        let seed_ciphertext = seal_secret(dek, secret, Self::AAD);

        let mut kid = Protection::GcpKms.prefix().to_string();
        kid.push_str(key_id);

        SecretEnvelope {
            key_id: kid,
            dek_ct: dek_ciphertext,
            secret_ct: seed_ciphertext,
        }
    }

    pub async fn decrypt_secret(envelope: &SecretEnvelope) -> Secret {
        // Extract the GCP KMS key ID from the envelope
        let key_id = envelope
            .key_id
            .strip_prefix(Protection::GcpKms.prefix())
            .unwrap_or_else(|| panic!("invalid GCP KMS key ID prefix: {}", envelope.key_id));

        // Decrypt the DEK using GCP KMS
        let dek = Self::open_dek(&envelope.dek_ct, key_id).await;

        // Use the DEK to decrypt the seed
        open_secret(dek, &envelope.secret_ct, Self::AAD).expect("failed to decrypt secret")
    }

    async fn seal_dek(dek: [u8; 32], key_id: &str) -> Vec<u8> {
        let client = google_cloud_kms_v1::client::KeyManagementService::builder()
            .with_tracing()
            .build()
            .await
            .expect("failed to create GCP KMS client");

        let dek_crc32c = crc32c::crc32c(&dek);

        let dek_result = client
            .encrypt()
            .set_name(key_id)
            .set_plaintext(dek.to_vec())
            .set_plaintext_crc32c(dek_crc32c)
            .set_additional_authenticated_data(Self::AAD)
            .send()
            .await
            .expect("call to GCP KMS encrypt failed");

        let ciphertext_crc32c = crc32c::crc32c(&dek_result.ciphertext);
        assert_eq!(
            dek_result.ciphertext_crc32c.unwrap() as u32,
            ciphertext_crc32c,
            "GCP ciphertext crc32c mismatch"
        );
        assert!(
            dek_result.name.starts_with(key_id),
            "mismatched key ID in GCP response"
        );
        assert!(
            dek_result.verified_plaintext_crc32c,
            "GCP KMS did not verify plaintext crc32c"
        );

        dek_result.ciphertext.to_vec()
    }

    async fn open_dek(dek_ciphertext: &[u8], key_id: &str) -> [u8; 32] {
        let client = google_cloud_kms_v1::client::KeyManagementService::builder()
            .with_tracing()
            .build()
            .await
            .expect("failed to create GCP KMS client");

        let ciphertext_crc32c = crc32c::crc32c(dek_ciphertext);

        let result = client
            .decrypt()
            .set_name(key_id)
            .set_ciphertext(dek_ciphertext.to_vec())
            .set_ciphertext_crc32c(ciphertext_crc32c)
            .set_additional_authenticated_data(Self::AAD)
            .send()
            .await
            .expect("call to GCP KMS decrypt failed");

        let plaintext_crc32c = crc32c::crc32c(&result.plaintext);
        assert_eq!(
            result.plaintext_crc32c.unwrap() as u32,
            plaintext_crc32c,
            "GCP plaintext crc32c mismatch"
        );

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&result.plaintext);
        dek
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Secret;

    #[cfg(feature = "longterm-gcp-kms")]
    #[tokio::test]
    #[ignore = "requires GCP credentials"]
    async fn encrypt_decrypt_secret_roundtrip() {
        // For GcpKms testing, use this key:
        let key_id = "projects/int08h-blog/locations/us-central1/keyRings/roughenough/cryptoKeys/roughenough-int08h";

        // Create a test secret
        let original_secret = Secret::new_random();
        let original_bytes = original_secret.expose().to_vec();

        // Encrypt the secret
        let envelope = GcpKms::encrypt_secret(key_id, &original_secret).await;

        // Verify the envelope contains the expected key ID
        assert!(envelope.key_id.starts_with(Protection::GcpKms.prefix()));
        assert!(envelope.key_id.contains(key_id));

        // Verify that encrypted data is present
        assert!(!envelope.dek_ct.is_empty());
        assert!(!envelope.secret_ct.is_empty());

        // Decrypt the secret
        let decrypted_secret = GcpKms::decrypt_secret(&envelope).await;

        // Verify the decrypted seed matches the original
        assert_eq!(decrypted_secret.expose(), &original_bytes);
    }

    #[cfg(feature = "longterm-gcp-kms")]
    #[test]
    fn envelope_serialization() {
        use serde_json;

        let envelope = SecretEnvelope {
            key_id: "gcp-kms://projects/test/locations/global/keyRings/test/cryptoKeys/test"
                .to_string(),
            dek_ct: vec![1, 2, 3, 4, 5],
            secret_ct: vec![6, 7, 8, 9, 10],
        };

        // Serialize to JSON
        let json = serde_json::to_string(&envelope).unwrap();

        // Deserialize back
        let deserialized: SecretEnvelope = serde_json::from_str(&json).unwrap();

        // Verify
        assert_eq!(envelope.key_id, deserialized.key_id);
        assert_eq!(envelope.dek_ct, deserialized.dek_ct);
        assert_eq!(envelope.secret_ct, deserialized.secret_ct);
    }
}
