use aws_sdk_secretsmanager::error::DisplayErrorContext;
use roughenough_protocol::util::as_hex;
use tracing::debug;

use crate::longterm::aws::sdk_config;
use crate::seed::Seed;
use crate::storage::{Protection, StorageError, decode_seed};

pub struct AwsSecretManager {}

impl AwsSecretManager {
    pub async fn get_seed(resource: &str) -> Result<Seed, StorageError> {
        debug!(
            "Attempting to load seed from AWS Secret Manager '{}'",
            resource
        );

        let config = sdk_config(resource).await?;
        let client = aws_sdk_secretsmanager::Client::new(&config);

        let response = client
            .get_secret_value()
            .secret_id(resource)
            .send()
            .await
            .map_err(|e| {
                StorageError::cloud(
                    Protection::AwsSecretManager.name(),
                    format!("get_secret_value failed: {}", DisplayErrorContext(&e)),
                )
            })?;

        let encoded_value = response.secret_string().ok_or_else(|| {
            StorageError::cloud(
                Protection::AwsSecretManager.name(),
                "secret value is missing",
            )
        })?;

        debug!(
            "Read a {}-byte value from AWS Secret Manager",
            encoded_value.len()
        );

        decode_secret_string(encoded_value)
    }

    pub async fn store_seed(resource: &str, seed: &Seed) -> Result<(), StorageError> {
        debug!(
            "Attempting to store seed in AWS Secret Manager '{}'",
            resource
        );

        let seed_hex = as_hex(seed.expose());
        let config = sdk_config(resource).await?;
        let client = aws_sdk_secretsmanager::Client::new(&config);

        client
            .put_secret_value()
            .secret_id(resource)
            .secret_string(seed_hex)
            .send()
            .await
            .map_err(|e| {
                StorageError::cloud(
                    Protection::AwsSecretManager.name(),
                    format!("put_secret_value failed: {}", DisplayErrorContext(&e)),
                )
            })?;

        debug!("Successfully stored seed in AWS Secret Manager");
        Ok(())
    }
}

fn decode_secret_string(encoded_value: &str) -> Result<Seed, StorageError> {
    decode_seed(encoded_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_secret_string_decodes() {
        let hex = "ab".repeat(32);
        let seed = decode_secret_string(&hex).unwrap();
        assert_eq!(seed.expose(), &[0xab; 32]);
    }

    #[test]
    fn undecodable_secret_string_is_an_error_not_a_panic() {
        let result = decode_secret_string("!!! not valid hex or base64 !!!");
        assert!(matches!(result, Err(StorageError::DecodeError(_))));
    }

    #[test]
    fn wrong_length_secret_is_an_error_not_a_panic() {
        // Valid hex, but only 16 bytes
        let result = decode_secret_string(&"ab".repeat(16));
        assert!(matches!(result, Err(StorageError::InvalidSeed(_))));
    }
}
