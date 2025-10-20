use aws_config::{BehaviorVersion, Region};
use common::encoding::try_decode;
use protocol::util::as_hex;
use tracing::debug;

use crate::seed::Seed;

pub struct AwsSecretManager {}

impl AwsSecretManager {
    pub async fn get_seed(resource: &str) -> Seed {
        debug!(
            "Attempting to load seed from AWS Secret Manager '{}'",
            resource
        );

        let region = extract_aws_region(resource);

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
            .unwrap();

        let encoded_value = response.secret_string().expect("secret value is missing");
        debug!(
            "Read a {}-byte value from AWS Secret Manager",
            encoded_value.len()
        );

        let encoded_str = String::from_utf8_lossy(encoded_value.as_ref()).to_string();
        let value = try_decode(&encoded_str).expect("failed to decode secret value");
        debug!("Decoded a {}-byte value", value.len());

        Seed::new(&value)
    }

    pub async fn store_seed(resource: &str, seed: &Seed) -> Result<(), String> {
        debug!(
            "Attempting to store seed in AWS Secret Manager '{}'",
            resource
        );

        let region = extract_aws_region(resource);

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .load()
            .await;

        let seed_hex = as_hex(seed.expose());
        let client = aws_sdk_secretsmanager::Client::new(&config);

        let response = client
            .put_secret_value()
            .secret_id(resource)
            .secret_string(seed_hex)
            .send()
            .await;

        match response {
            Ok(_) => {
                debug!("Successfully stored seed in AWS Secret Manager");
                Ok(())
            }
            Err(err) => {
                debug!("Failed to store secret: {err}");
                Err(err.to_string())
            }
        }
    }
}
fn extract_aws_region(arn: &str) -> String {
    // "arn:aws:secretsmanager:us-east-2:382045063468:secret:roughenough-seed-QtQH5f";
    //                        ^
    arn.split(":").nth(3).unwrap().to_string()
}
