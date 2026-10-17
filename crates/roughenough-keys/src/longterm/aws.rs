use aws_config::{BehaviorVersion, Region, SdkConfig};

use crate::storage::StorageError;

/// SDK configuration for the region named in `arn`
pub(crate) async fn sdk_config(arn: &str) -> Result<SdkConfig, StorageError> {
    let region = extract_aws_region(arn)?;
    Ok(aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region))
        .load()
        .await)
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
        let arn1 = "arn:aws:secretsmanager:us-east-2:382045063468:secret:roughenough-foo-12345";
        assert_eq!(extract_aws_region(arn1).unwrap(), "us-east-2");

        let arn2 = "arn:aws:kms:us-east-1:382045063468:key/84e7ff78-7f16-4716-a300-12345678abcd";
        assert_eq!(extract_aws_region(arn2).unwrap(), "us-east-1");
    }

    #[test]
    fn malformed_arn_is_an_error_not_a_panic() {
        for arn in ["not-an-arn", "arn:aws:kms", "arn:aws:kms::empty-region", ""] {
            assert!(matches!(
                extract_aws_region(arn),
                Err(StorageError::InvalidResource(_))
            ));
        }
    }
}
