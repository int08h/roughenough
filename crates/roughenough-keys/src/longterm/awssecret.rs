use aws_config::{BehaviorVersion, Region};
use aws_sdk_secretsmanager::error::DisplayErrorContext;
use roughenough_common::encoding::try_decode;
use roughenough_protocol::util::as_hex;
use tracing::debug;
use zeroize::Zeroizing;

use crate::seed::Seed;
use crate::storage::StorageError;

pub struct AwsSecretManager {}

impl AwsSecretManager {
    const BACKEND: &'static str = "AWS Secret Manager";

    fn error(detail: impl Into<String>) -> StorageError {
        StorageError::CloudBackend {
            backend: Self::BACKEND,
            detail: detail.into(),
        }
    }

    pub async fn get_seed(resource: &str) -> Result<Seed, StorageError> {
        debug!(
            "Attempting to load seed from AWS Secret Manager '{}'",
            resource
        );

        let region = extract_aws_region(resource)?;

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .load()
            .await;

        let client = aws_sdk_secretsmanager::Client::new(&config);

        let response = client
            .get_secret_value()
            .secret_id(resource)
            .send()
            .await
            .map_err(|e| {
                Self::error(format!(
                    "get_secret_value failed: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        let encoded_value = response
            .secret_string()
            .ok_or_else(|| Self::error("secret value is missing"))?;

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

        let region = extract_aws_region(resource)?;

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .load()
            .await;

        let seed_hex = as_hex(seed.expose());
        let client = aws_sdk_secretsmanager::Client::new(&config);

        client
            .put_secret_value()
            .secret_id(resource)
            .secret_string(seed_hex)
            .send()
            .await
            .map_err(|e| {
                Self::error(format!(
                    "put_secret_value failed: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        debug!("Successfully stored seed in AWS Secret Manager");
        Ok(())
    }
}

fn decode_secret_string(encoded_value: &str) -> Result<Seed, StorageError> {
    let value = Zeroizing::new(try_decode(encoded_value)?);
    debug!("Decoded a {}-byte value", value.len());

    if value.len() != 32 {
        return Err(StorageError::InvalidSeed(format!(
            "need 32 bytes, found: {}",
            value.len()
        )));
    }

    Ok(Seed::new(&value))
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
    use super::*;

    #[test]
    fn region_is_extracted_from_arn() {
        let arn = "arn:aws:secretsmanager:us-east-2:382045063468:secret:roughenough-seed-QtQH5f";
        assert_eq!(extract_aws_region(arn).unwrap(), "us-east-2");
    }

    #[test]
    fn malformed_arn_is_an_error_not_a_panic() {
        assert!(matches!(
            extract_aws_region("no-colons-here"),
            Err(StorageError::InvalidResource(_))
        ));
        assert!(matches!(
            extract_aws_region(""),
            Err(StorageError::InvalidResource(_))
        ));
    }

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
