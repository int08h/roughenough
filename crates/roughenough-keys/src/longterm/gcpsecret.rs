use roughenough_common::encoding::try_decode;
use roughenough_protocol::util::as_hex;
use tracing::debug;

use crate::seed::Seed;
use crate::storage::StorageError;

// projects/630192955771/secrets/roughenough-seed-test-1/versions/1
// https://cloud.google.com/docs/authentication/application-default-credentials
pub struct GcpSecretManager {}

impl GcpSecretManager {
    const BACKEND: &'static str = "GCP Secret Manager";

    fn error(detail: impl Into<String>) -> StorageError {
        StorageError::CloudBackend {
            backend: Self::BACKEND,
            detail: detail.into(),
        }
    }

    pub async fn get_seed(resource: &str) -> Result<Seed, StorageError> {
        debug!(
            "Attempting to load seed from GCP Secret Manager '{}'",
            resource
        );

        let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
            .with_tracing()
            .build()
            .await
            .map_err(|e| Self::error(format!("failed to create client: {e}")))?;

        let result = client
            .access_secret_version()
            .set_name(resource)
            .send()
            .await
            .map_err(|e| Self::error(format!("access_secret_version failed: {e}")))?;

        let payload = result
            .payload
            .ok_or_else(|| Self::error("secret value is missing"))?;

        debug!(
            "Read a {}-byte value from GCP Secret Manager",
            payload.data.len()
        );

        decode_secret_payload(&payload.data, payload.data_crc32c)
    }

    pub async fn store_seed(resource: &str, seed: &Seed) -> Result<String, StorageError> {
        debug!(
            "Attempting to store seed in GCP Secret Manager '{}'",
            resource
        );

        let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
            .with_tracing()
            .build()
            .await
            .map_err(|e| Self::error(format!("failed to create client: {e}")))?;

        let seed_hex = as_hex(seed.expose());
        let mut payload = google_cloud_secretmanager_v1::model::SecretPayload::default();
        payload.data = seed_hex.into_bytes().into();
        payload.data_crc32c = Some(crc32c::crc32c(&payload.data) as i64);

        let parent = extract_secret_parent(resource)?;

        let version = client
            .add_secret_version()
            .set_parent(&parent)
            .set_payload(payload)
            .send()
            .await
            .map_err(|e| Self::error(format!("add_secret_version failed: {e}")))?;

        debug!("Successfully stored seed as version: {}", version.name);
        Ok(version.name)
    }
}

fn decode_secret_payload(data: &[u8], data_crc32c: Option<i64>) -> Result<Seed, StorageError> {
    if let Some(expected) = data_crc32c {
        let computed = crc32c::crc32c(data) as i64;
        if expected != computed {
            return Err(StorageError::IntegrityCheckFailed(format!(
                "secret value crc32c mismatch: response says {expected:#x}, computed {computed:#x}"
            )));
        }
    }

    let encoded_str = String::from_utf8_lossy(data).to_string();
    let value = try_decode(&encoded_str)?;
    debug!("Decoded a {}-byte value", value.len());

    if value.len() != 32 {
        return Err(StorageError::InvalidSeed(format!(
            "need 32 bytes, found: {}",
            value.len()
        )));
    }

    Ok(Seed::new(&value))
}

/// projects/{project}/secrets/{secret}/versions/{version}
/// -----------------------------------
fn extract_secret_parent(resource: &str) -> Result<String, StorageError> {
    let parts: Vec<&str> = resource.split('/').collect();

    if parts.len() < 4 || parts[0] != "projects" || parts[2] != "secrets" {
        return Err(StorageError::InvalidResource(format!(
            "invalid resource format: {resource}"
        )));
    }

    if parts.len() == 4 {
        return Ok(resource.to_string());
    }

    Ok(format!(
        "{}/{}/{}/{}",
        parts[0], parts[1], parts[2], parts[3]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_secret_parent() {
        assert_eq!(
            extract_secret_parent(
                "projects/630192955771/secrets/roughenough-seed-test-1/versions/1"
            )
            .unwrap(),
            "projects/630192955771/secrets/roughenough-seed-test-1".to_string()
        );

        // Test already parent format
        assert_eq!(
            extract_secret_parent("projects/630192955771/secrets/roughenough-seed-test-1").unwrap(),
            "projects/630192955771/secrets/roughenough-seed-test-1".to_string()
        );

        // Test invalid formats
        assert!(extract_secret_parent("invalid/path").is_err());
        assert!(extract_secret_parent("projects/123").is_err());
        assert!(extract_secret_parent("").is_err());
    }

    #[test]
    fn valid_payload_decodes() {
        let hex = "cd".repeat(32);
        let crc = crc32c::crc32c(hex.as_bytes()) as i64;

        let seed = decode_secret_payload(hex.as_bytes(), Some(crc)).unwrap();
        assert_eq!(seed.expose(), &[0xcd; 32]);

        // A missing crc32c is accepted (nothing to verify against)
        let seed = decode_secret_payload(hex.as_bytes(), None).unwrap();
        assert_eq!(seed.expose(), &[0xcd; 32]);
    }

    #[test]
    fn crc32c_mismatch_is_an_error_not_a_panic() {
        let hex = "cd".repeat(32);
        let bad_crc = crc32c::crc32c(hex.as_bytes()) as i64 + 1;

        let result = decode_secret_payload(hex.as_bytes(), Some(bad_crc));
        assert!(matches!(result, Err(StorageError::IntegrityCheckFailed(_))));
    }

    #[test]
    fn undecodable_payload_is_an_error_not_a_panic() {
        let data = b"!!! not valid hex or base64 !!!";
        let crc = crc32c::crc32c(data) as i64;
        let result = decode_secret_payload(data, Some(crc));
        assert!(matches!(result, Err(StorageError::DecodeError(_))));
    }

    #[test]
    fn wrong_length_payload_is_an_error_not_a_panic() {
        let hex = "cd".repeat(16); // valid hex, only 16 bytes
        let crc = crc32c::crc32c(hex.as_bytes()) as i64;
        let result = decode_secret_payload(hex.as_bytes(), Some(crc));
        assert!(matches!(result, Err(StorageError::InvalidSeed(_))));
    }
}
