use common::encoding::try_decode;
use protocol::util::as_hex;
use tracing::debug;

use crate::seed::Seed;

// projects/630192955771/secrets/roughenough-seed-test-1/versions/1
// https://cloud.google.com/docs/authentication/application-default-credentials
pub struct GcpSecretManager {}

impl GcpSecretManager {
    pub async fn get_seed(resource: &str) -> Seed {
        debug!(
            "Attempting to load seed from GCP Secret Manager '{}'",
            resource
        );

        let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
            .with_tracing()
            .build()
            .await
            .expect("failed to create GCP secret manager client");

        let result = client
            .access_secret_version()
            .set_name(resource)
            .send()
            .await
            .expect("call to access the secret failed");

        let payload = result.payload.expect("secret value is missing");

        let encoded_value = payload.data.to_vec();
        debug!(
            "Read a {}-byte value from GCP Secret Manager",
            encoded_value.len()
        );

        if let Some(data_crc32c) = payload.data_crc32c {
            let computed_crc32c = crc32c::crc32c(&encoded_value);
            debug!(
                "secret value crc32c: {:x}, computed crc32c: {:x}",
                data_crc32c, computed_crc32c
            );
            assert_eq!(
                data_crc32c as u32, computed_crc32c,
                "secret value checksum mismatch"
            );
        }

        let encoded_str = String::from_utf8_lossy(&encoded_value).to_string();
        let value = try_decode(&encoded_str).expect("failed to decode secret value");
        debug!("Decoded a {}-byte value", value.len());

        Seed::new(&value)
    }

    pub async fn store_seed(resource: &str, seed: &Seed) -> Result<String, String> {
        debug!(
            "Attempting to store seed in GCP Secret Manager '{}'",
            resource
        );

        let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
            .with_tracing()
            .build()
            .await
            .map_err(|e| format!("failed to create GCP secret manager client: {e}"))?;

        let seed_hex = as_hex(seed.expose());
        let mut payload = google_cloud_secretmanager_v1::model::SecretPayload::default();
        payload.data = seed_hex.into_bytes().into();
        payload.data_crc32c = Some(crc32c::crc32c(&payload.data) as i64);

        let parent = extract_secret_parent(resource)?;

        let response = client
            .add_secret_version()
            .set_parent(&parent)
            .set_payload(payload)
            .send()
            .await;

        match response {
            Ok(version) => {
                debug!("Successfully stored seed as version: {}", version.name);
                Ok(version.name)
            }
            Err(err) => Err(format!("failed to store secret: {err}")),
        }
    }
}

/// projects/{project}/secrets/{secret}/versions/{version}
/// -----------------------------------
fn extract_secret_parent(resource: &str) -> Result<String, String> {
    let parts: Vec<&str> = resource.split('/').collect();

    if parts.len() < 4 || parts[0] != "projects" || parts[2] != "secrets" {
        return Err(format!("Invalid resource format: {resource}"));
    }

    if parts.len() == 4 {
        return Ok(resource.to_string());
    }

    if parts.len() > 4 {
        return Ok(format!(
            "{}/{}/{}/{}",
            parts[0], parts[1], parts[2], parts[3]
        ));
    }

    Err(format!("Invalid resource format: {resource}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_secret_parent() {
        assert_eq!(
            extract_secret_parent(
                "projects/630192955771/secrets/roughenough-seed-test-1/versions/1"
            ),
            Ok("projects/630192955771/secrets/roughenough-seed-test-1".to_string())
        );

        // Test already parent format
        assert_eq!(
            extract_secret_parent("projects/630192955771/secrets/roughenough-seed-test-1"),
            Ok("projects/630192955771/secrets/roughenough-seed-test-1".to_string())
        );

        // Test invalid formats
        assert!(extract_secret_parent("invalid/path").is_err());
        assert!(extract_secret_parent("projects/123").is_err());
        assert!(extract_secret_parent("").is_err());
    }
}
