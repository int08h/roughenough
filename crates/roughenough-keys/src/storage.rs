use roughenough_common::encoding;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::longterm::envelope::SeedEnvelope;
use crate::seed::Seed;

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("{0}")]
    InvalidSeed(String),

    #[error("{0}")]
    NotImplemented(String),

    #[error("Decoding seed: {0}")]
    DecodeError(#[from] data_encoding::DecodeError),

    #[error("Parsing seed envelope: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("{backend} error: {detail}")]
    CloudBackend {
        backend: &'static str,
        detail: String,
    },

    #[error("integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    #[error("invalid resource: {0}")]
    InvalidResource(String),
}

/// Loads the seed from secure long-term storage and transfers it to an online backend. This is a
/// convenience function that drives `try_load_seed` to completion internally.
pub fn try_load_seed_sync(encoded_value: &str) -> Result<Seed, StorageError> {
    crate::runtime::block_on(try_load_seed(encoded_value))
}

/// Loads the seed from secure long-term storage and transfers it to an online backend.
pub async fn try_load_seed(encoded_value: &str) -> Result<Seed, StorageError> {
    // Never log the value itself: for the seed:// scheme it IS the seed
    trace!("Loading a {}-character seed value", encoded_value.len());

    match Protection::from_prefix(encoded_value) {
        Some(method) => {
            debug!("Seed protection method: {:?}", method);
            let value = encoded_value.strip_prefix(method.prefix()).unwrap();
            Ok(method.try_load(value).await?)
        }
        None => {
            debug!("No seed protection prefix, assuming plain text");
            Protection::Plain.try_load(encoded_value).await
        }
    }
}

pub async fn try_store_seed(seed: &Seed, resource_id: &str) -> Result<SeedEnvelope, StorageError> {
    trace!("Storing seed for {}", resource_id);

    match Protection::from_prefix(resource_id) {
        Some(method) => {
            debug!("Seed protection method: {:?}", method);
            let resource_id = resource_id.strip_prefix(method.prefix()).unwrap();
            method.try_store(seed, resource_id).await
        }
        None => Err(StorageError::InvalidSeed(
            "no protection method specified in resource".to_string(),
        )),
    }
}

/// Methods of secure long-term storage for the server's identity.
#[derive(Debug, Eq, PartialEq)]
pub enum Protection {
    Plain,
    AwsKms,
    GcpKms,
    AwsSecretManager,
    GcpSecretManager,
}

impl Protection {
    pub fn from_prefix(prefix: &str) -> Option<Protection> {
        if prefix.starts_with("aws-kms://") {
            Some(Protection::AwsKms)
        } else if prefix.starts_with("aws-secret://") {
            Some(Protection::AwsSecretManager)
        } else if prefix.starts_with("gcp-kms://") {
            Some(Protection::GcpKms)
        } else if prefix.starts_with("gcp-secret://") {
            Some(Protection::GcpSecretManager)
        } else if prefix.starts_with("seed://") {
            Some(Protection::Plain)
        } else {
            None
        }
    }

    pub fn prefix(&self) -> &str {
        match self {
            Protection::Plain => "seed://",
            Protection::AwsKms => "aws-kms://",
            Protection::GcpKms => "gcp-kms://",
            Protection::AwsSecretManager => "aws-secret://",
            Protection::GcpSecretManager => "gcp-secret://",
        }
    }

    /// Encode `envelope` as the single-line prefixed form that `try_load_seed`
    /// accepts, suitable for writing directly to a server seed file.
    pub fn encode_envelope(&self, envelope: &SeedEnvelope) -> Result<String, StorageError> {
        let json = serde_json::to_vec(envelope)?;
        let encoded = data_encoding::BASE64URL.encode(&json);
        Ok(format!("{}{}", self.prefix(), encoded))
    }

    async fn try_load(&self, value: &str) -> Result<Seed, StorageError> {
        match self {
            Protection::Plain => self.try_load_plain(value).await,
            Protection::AwsKms => self.try_load_aws_kms(value).await,
            Protection::GcpKms => self.try_load_gcp_kms(value).await,
            Protection::AwsSecretManager => self.try_load_aws_secret_manager(value).await,
            Protection::GcpSecretManager => self.try_load_gcp_secret_manager(value).await,
        }
    }

    async fn try_store(
        &self,
        seed: &Seed,
        resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        match self {
            Protection::AwsKms => self.try_store_aws_kms(seed, resource_id).await,
            Protection::GcpKms => self.try_store_gcp_kms(seed, resource_id).await,
            Protection::AwsSecretManager => {
                self.try_store_aws_secret_manager(seed, resource_id).await
            }
            Protection::GcpSecretManager => {
                self.try_store_gcp_secret_manager(seed, resource_id).await
            }
            Protection::Plain => Err(StorageError::NotImplemented(
                "a 'seed://' value is the seed itself; storing it is a no-op by design".to_string(),
            )),
        }
    }

    async fn try_load_plain(&self, value: &str) -> Result<Seed, StorageError> {
        let data = Zeroizing::new(encoding::try_decode(value)?);
        if data.len() != 32 {
            let msg = format!("need 32 bytes, found: {0}", data.len());
            return Err(StorageError::InvalidSeed(msg));
        }
        Ok(Seed::new(&data))
    }

    #[cfg(feature = "longterm-aws-kms")]
    async fn try_load_aws_kms(&self, value: &str) -> Result<Seed, StorageError> {
        use crate::longterm::awskms::AwsKms;
        use crate::longterm::envelope::SeedEnvelope;

        let json_envelope = encoding::try_decode(value)?;
        let seed_envelope = serde_json::from_slice::<SeedEnvelope>(&json_envelope)?;

        debug!("AWS KMS key: {}", seed_envelope.key_id);

        AwsKms::decrypt_seed(&seed_envelope).await
    }

    #[cfg(not(feature = "longterm-aws-kms"))]
    async fn try_load_aws_kms(&self, _value: &str) -> Result<Seed, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg =
            "AWS KMS is not enabled. Recompile with the 'longterm-aws-kms' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-aws-kms")]
    async fn try_store_aws_kms(
        &self,
        seed: &Seed,
        resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        use crate::longterm::awskms::AwsKms;
        AwsKms::encrypt_seed(resource_id, seed).await
    }

    #[cfg(not(feature = "longterm-aws-kms"))]
    async fn try_store_aws_kms(
        &self,
        _seed: &Seed,
        _resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg =
            "AWS KMS is not enabled. Recompile with the 'longterm-aws-kms' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-gcp-kms")]
    async fn try_load_gcp_kms(&self, value: &str) -> Result<Seed, StorageError> {
        use crate::longterm::envelope::SeedEnvelope;
        use crate::longterm::gcpkms::GcpKms;

        let json_envelope = encoding::try_decode(value)?;
        let seed_envelope = serde_json::from_slice::<SeedEnvelope>(&json_envelope)?;

        debug!("GCP KMS key: {}", seed_envelope.key_id);

        GcpKms::decrypt_seed(&seed_envelope).await
    }

    #[cfg(not(feature = "longterm-gcp-kms"))]
    async fn try_load_gcp_kms(&self, _value: &str) -> Result<Seed, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg =
            "GCP KMS is not enabled. Recompile with the 'longterm-gcp-kms' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-aws-secret-manager")]
    async fn try_load_aws_secret_manager(&self, value: &str) -> Result<Seed, StorageError> {
        use crate::longterm::awssecret::AwsSecretManager;
        use crate::longterm::envelope::SeedEnvelope;

        let json_envelope = encoding::try_decode(value)?;
        let seed_envelope = serde_json::from_slice::<SeedEnvelope>(&json_envelope)?;

        let prefix = Protection::AwsSecretManager.prefix();
        let secret_id = seed_envelope.key_id.strip_prefix(prefix).ok_or_else(|| {
            StorageError::InvalidResource(format!(
                "envelope key id '{}' lacks the '{}' prefix",
                seed_envelope.key_id, prefix
            ))
        })?;

        debug!("AWS Secret Manager secret: {}", secret_id);

        AwsSecretManager::get_seed(secret_id).await
    }

    #[cfg(not(feature = "longterm-aws-secret-manager"))]
    async fn try_load_aws_secret_manager(&self, _value: &str) -> Result<Seed, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg = "AWS Secret Manager is not enabled. Recompile with the 'longterm-aws-secret-manager' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-aws-secret-manager")]
    async fn try_store_aws_secret_manager(
        &self,
        seed: &Seed,
        resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        use crate::longterm::awssecret::AwsSecretManager;
        use crate::longterm::envelope::SeedEnvelope;

        AwsSecretManager::store_seed(resource_id, seed).await?;

        Ok(SeedEnvelope {
            key_id: format!("{}{}", Protection::AwsSecretManager.prefix(), resource_id),
            seed_ct: vec![],
            dek_ct: vec![],
        })
    }

    #[cfg(not(feature = "longterm-aws-secret-manager"))]
    async fn try_store_aws_secret_manager(
        &self,
        _seed: &Seed,
        _resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg = "AWS Secret Manager is not enabled. Recompile with the 'longterm-aws-secret-manager' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-gcp-secret-manager")]
    async fn try_load_gcp_secret_manager(&self, value: &str) -> Result<Seed, StorageError> {
        use crate::longterm::gcpsecret::GcpSecretManager;

        let json_envelope = encoding::try_decode(value)?;
        let seed_envelope = serde_json::from_slice::<SeedEnvelope>(&json_envelope)?;

        let prefix = Protection::GcpSecretManager.prefix();
        let secret_id = seed_envelope.key_id.strip_prefix(prefix).ok_or_else(|| {
            StorageError::InvalidResource(format!(
                "envelope key id '{}' lacks the '{}' prefix",
                seed_envelope.key_id, prefix
            ))
        })?;

        GcpSecretManager::get_seed(secret_id).await
    }

    #[cfg(not(feature = "longterm-gcp-secret-manager"))]
    async fn try_load_gcp_secret_manager(&self, _value: &str) -> Result<Seed, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg = "GCP Secret Manager is not enabled. Recompile with the 'longterm-gcp-secret-manager' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-gcp-secret-manager")]
    async fn try_store_gcp_secret_manager(
        &self,
        seed: &Seed,
        resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        use crate::longterm::envelope::SeedEnvelope;
        use crate::longterm::gcpsecret::GcpSecretManager;

        let version = GcpSecretManager::store_seed(resource_id, seed).await?;

        Ok(SeedEnvelope {
            key_id: format!("{}{}", Protection::GcpSecretManager.prefix(), version),
            seed_ct: vec![],
            dek_ct: vec![],
        })
    }

    #[cfg(not(feature = "longterm-gcp-secret-manager"))]
    async fn try_store_gcp_secret_manager(
        &self,
        _seed: &Seed,
        _resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg = "GCP Secret Manager is not enabled. Recompile with the 'longterm-gcp-secret-manager' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-gcp-kms")]
    async fn try_store_gcp_kms(
        &self,
        seed: &Seed,
        resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        use crate::longterm::gcpkms::GcpKms;

        GcpKms::encrypt_seed(resource_id, seed).await
    }

    #[cfg(not(feature = "longterm-gcp-kms"))]
    async fn try_store_gcp_kms(
        &self,
        _seed: &Seed,
        _resource_id: &str,
    ) -> Result<SeedEnvelope, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg =
            "GCP KMS is not enabled. Recompile with the 'longterm-gcp-kms' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::block_on;

    #[test]
    fn from_prefix_routes_every_scheme() {
        assert_eq!(
            Protection::from_prefix("seed://aabb"),
            Some(Protection::Plain)
        );
        assert_eq!(
            Protection::from_prefix("aws-kms://arn:aws:kms:us-east-2:1:key/x"),
            Some(Protection::AwsKms)
        );
        assert_eq!(
            Protection::from_prefix("gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k"),
            Some(Protection::GcpKms)
        );
        assert_eq!(
            Protection::from_prefix("aws-secret://arn:aws:secretsmanager:us-east-2:1:secret:x"),
            Some(Protection::AwsSecretManager)
        );
        assert_eq!(
            Protection::from_prefix("gcp-secret://projects/p/secrets/s/versions/1"),
            Some(Protection::GcpSecretManager)
        );

        assert_eq!(Protection::from_prefix("vault://something"), None);
        assert_eq!(Protection::from_prefix("aabbccdd"), None);
        assert_eq!(Protection::from_prefix(""), None);
    }

    #[test]
    fn prefix_round_trips_through_from_prefix() {
        for method in [
            Protection::Plain,
            Protection::AwsKms,
            Protection::GcpKms,
            Protection::AwsSecretManager,
            Protection::GcpSecretManager,
        ] {
            let value = format!("{}whatever", method.prefix());
            assert_eq!(Protection::from_prefix(&value), Some(method));
        }
    }

    #[test]
    fn storing_a_plain_seed_is_an_error_not_a_panic() {
        let seed = Seed::new(&[7u8; 32]);
        let result = block_on(try_store_seed(&seed, "seed://aabbccdd"));

        match result {
            Err(StorageError::NotImplemented(msg)) => {
                assert!(msg.contains("no-op by design"), "unexpected: {msg}")
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn storing_with_unknown_scheme_is_an_error() {
        let seed = Seed::new(&[7u8; 32]);
        let result = block_on(try_store_seed(&seed, "vault://something"));
        assert!(matches!(result, Err(StorageError::InvalidSeed(_))));
    }

    #[test]
    fn plain_seed_loads_from_hex() {
        let value = format!("seed://{}", "aa".repeat(32));
        let seed = block_on(try_load_seed(&value)).unwrap();
        assert_eq!(seed.expose(), &[0xaa; 32]);

        // No prefix falls back to plain
        let seed = block_on(try_load_seed(&"bb".repeat(32))).unwrap();
        assert_eq!(seed.expose(), &[0xbb; 32]);
    }

    #[test]
    fn plain_seed_with_wrong_length_is_an_error() {
        let result = block_on(try_load_seed("seed://aabbcc"));
        assert!(matches!(result, Err(StorageError::InvalidSeed(_))));
    }

    #[cfg(not(feature = "longterm-aws-kms"))]
    #[test]
    fn aws_kms_without_feature_is_not_implemented() {
        let seed = Seed::new(&[7u8; 32]);
        let load = block_on(try_load_seed("aws-kms://whatever"));
        assert!(matches!(load, Err(StorageError::NotImplemented(_))));
        let store = block_on(try_store_seed(&seed, "aws-kms://whatever"));
        assert!(matches!(store, Err(StorageError::NotImplemented(_))));
    }

    #[cfg(not(feature = "longterm-gcp-kms"))]
    #[test]
    fn gcp_kms_without_feature_is_not_implemented() {
        let seed = Seed::new(&[7u8; 32]);
        let load = block_on(try_load_seed("gcp-kms://whatever"));
        assert!(matches!(load, Err(StorageError::NotImplemented(_))));
        let store = block_on(try_store_seed(&seed, "gcp-kms://whatever"));
        assert!(matches!(store, Err(StorageError::NotImplemented(_))));
    }

    #[cfg(not(feature = "longterm-aws-secret-manager"))]
    #[test]
    fn aws_secret_manager_without_feature_is_not_implemented() {
        let seed = Seed::new(&[7u8; 32]);
        let load = block_on(try_load_seed("aws-secret://whatever"));
        assert!(matches!(load, Err(StorageError::NotImplemented(_))));
        let store = block_on(try_store_seed(&seed, "aws-secret://whatever"));
        assert!(matches!(store, Err(StorageError::NotImplemented(_))));
    }

    #[cfg(not(feature = "longterm-gcp-secret-manager"))]
    #[test]
    fn gcp_secret_manager_without_feature_is_not_implemented() {
        let seed = Seed::new(&[7u8; 32]);
        let load = block_on(try_load_seed("gcp-secret://whatever"));
        assert!(matches!(load, Err(StorageError::NotImplemented(_))));
        let store = block_on(try_store_seed(&seed, "gcp-secret://whatever"));
        assert!(matches!(store, Err(StorageError::NotImplemented(_))));
    }

    #[test]
    fn encoded_envelope_round_trips_through_load_dispatch() {
        let envelope = SeedEnvelope {
            key_id: "aws-secret://arn:aws:secretsmanager:us-east-2:1:secret:x".to_string(),
            seed_ct: vec![],
            dek_ct: vec![],
        };

        let encoded = Protection::AwsSecretManager
            .encode_envelope(&envelope)
            .unwrap();

        // The load dispatch selects the correct Protection variant
        assert_eq!(
            Protection::from_prefix(&encoded),
            Some(Protection::AwsSecretManager)
        );

        // And the value after the prefix decodes back to the same envelope
        let value = encoded
            .strip_prefix(Protection::AwsSecretManager.prefix())
            .unwrap();
        let json = encoding::try_decode(value).unwrap();
        let parsed: SeedEnvelope = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.key_id, envelope.key_id);
        assert!(parsed.seed_ct.is_empty());
        assert!(parsed.dek_ct.is_empty());
    }

    #[test]
    fn encoded_kms_envelope_preserves_ciphertexts() {
        let envelope = SeedEnvelope {
            key_id: "aws-kms://arn:aws:kms:us-east-2:1:key/x".to_string(),
            seed_ct: vec![1, 2, 3],
            dek_ct: vec![4, 5, 6],
        };

        let encoded = Protection::AwsKms.encode_envelope(&envelope).unwrap();
        assert_eq!(Protection::from_prefix(&encoded), Some(Protection::AwsKms));

        let value = encoded.strip_prefix(Protection::AwsKms.prefix()).unwrap();
        let json = encoding::try_decode(value).unwrap();
        let parsed: SeedEnvelope = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.key_id, envelope.key_id);
        assert_eq!(parsed.seed_ct, envelope.seed_ct);
        assert_eq!(parsed.dek_ct, envelope.dek_ct);
    }

    #[test]
    fn storage_error_display_formats() {
        let err = StorageError::CloudBackend {
            backend: "AWS KMS",
            detail: "call failed".to_string(),
        };
        assert_eq!(err.to_string(), "AWS KMS error: call failed");

        let err = StorageError::IntegrityCheckFailed("crc32c mismatch".to_string());
        assert_eq!(err.to_string(), "integrity check failed: crc32c mismatch");

        let err = StorageError::InvalidResource("bad arn".to_string());
        assert_eq!(err.to_string(), "invalid resource: bad arn");

        let err = StorageError::InvalidSeed("need 32 bytes".to_string());
        assert_eq!(err.to_string(), "need 32 bytes");

        let err = StorageError::NotImplemented("feature off".to_string());
        assert_eq!(err.to_string(), "feature off");
    }
}
