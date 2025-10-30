use roughenough_common::encoding;
use tracing::{debug, error, trace};

use crate::longterm::envelope::SecretEnvelope;
use crate::seed::Secret;

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("{0}")]
    InvalidSecret(String),

    #[error("{0}")]
    NotImplemented(String),

    #[error("Decoding secret: {0}")]
    DecodeError(#[from] data_encoding::DecodeError),

    #[error("Parsing secret envelope: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("secret manager error: {0}")]
    SecretManager(String),
}

/// Loads a secret from secure long-term storage and transfers it to an online backend. This is a
/// convenience function that uses an async runtime internally to call `try_load_secret`.
pub fn try_load_secret_sync(encoded_value: &str) -> Result<Secret, StorageError> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(try_load_secret(encoded_value))
}

/// Loads a secret from secure long-term storage and transfers it to an online backend.
pub async fn try_load_secret(encoded_value: &str) -> Result<Secret, StorageError> {
    trace!("Loading secret from {}", encoded_value);

    match Protection::from_prefix(encoded_value) {
        Some(method) => {
            debug!("Seed protection method: {:?}", method);
            let value = encoded_value.strip_prefix(method.prefix()).unwrap();
            Ok(method.try_load(value).await?)
        }
        None => {
            debug!("No secret protection prefix, assuming plain text");
            Protection::Plain.try_load(encoded_value).await
        }
    }
}

pub async fn try_store_secret(
    secret: &Secret,
    resource_id: &str,
) -> Result<SecretEnvelope, StorageError> {
    trace!("Storing secret for {}", resource_id);

    match Protection::from_prefix(resource_id) {
        Some(method) => {
            debug!("Seed protection method: {:?}", method);
            let resource_id = resource_id.strip_prefix(method.prefix()).unwrap();
            method.try_store(secret, resource_id).await
        }
        None => Err(StorageError::InvalidSecret(
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
        } else if prefix.starts_with("secret://") {
            Some(Protection::Plain)
        } else {
            None
        }
    }

    pub fn prefix(&self) -> &str {
        match self {
            Protection::Plain => "secret://",
            Protection::AwsKms => "aws-kms://",
            Protection::GcpKms => "gcp-kms://",
            Protection::AwsSecretManager => "aws-secret://",
            Protection::GcpSecretManager => "gcp-secret://",
        }
    }

    async fn try_load(&self, value: &str) -> Result<Secret, StorageError> {
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
        secret: &Secret,
        resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        match self {
            Protection::AwsKms => self.try_store_aws_kms(secret, resource_id).await,
            Protection::GcpKms => self.try_store_gcp_kms(secret, resource_id).await,
            Protection::AwsSecretManager => {
                self.try_store_aws_secret_manager(secret, resource_id).await
            }
            Protection::GcpSecretManager => {
                self.try_store_gcp_secret_manager(secret, resource_id).await
            }
            Protection::Plain => {
                unreachable!("Plain protection method should not be used for storing seeds");
            }
        }
    }

    async fn try_load_plain(&self, value: &str) -> Result<Secret, StorageError> {
        let data = encoding::try_decode(value)?;
        if data.len() != 32 {
            let msg = format!("need 32 bytes, found: {0}", data.len());
            return Err(StorageError::InvalidSecret(msg));
        }
        Ok(Secret::new(&data))
    }

    #[cfg(feature = "longterm-aws-kms")]
    async fn try_load_aws_kms(&self, value: &str) -> Result<Secret, StorageError> {
        use crate::longterm::awskms::AwsKms;
        use crate::longterm::envelope::SecretEnvelope;

        let json_envelope = encoding::try_decode(value)?;
        let seed_envelope = serde_json::from_slice::<SecretEnvelope>(&json_envelope)?;

        debug!("AWS KMS key: {}", seed_envelope.key_id);

        let secret = AwsKms::decrypt_secret(&seed_envelope).await;
        Ok(secret)
    }

    #[cfg(not(feature = "longterm-aws-kms"))]
    async fn try_load_aws_kms(&self, _value: &str) -> Result<Secret, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg =
            "AWS KMS is not enabled. Recompile with the 'longterm-aws-kms' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-aws-kms")]
    async fn try_store_aws_kms(
        &self,
        secret: &Secret,
        resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        use crate::longterm::awskms::AwsKms;
        Ok(AwsKms::encrypt_secret(resource_id, secret).await)
    }

    #[cfg(not(feature = "longterm-aws-kms"))]
    async fn try_store_aws_kms(
        &self,
        _secret: &Secret,
        _resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg =
            "AWS KMS is not enabled. Recompile with the 'longterm-aws-kms' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-gcp-kms")]
    async fn try_load_gcp_kms(&self, value: &str) -> Result<Secret, StorageError> {
        use crate::longterm::envelope::SecretEnvelope;
        use crate::longterm::gcpkms::GcpKms;

        let json_envelope = encoding::try_decode(value)?;
        let seed_envelope = serde_json::from_slice::<SecretEnvelope>(&json_envelope)?;

        debug!("GCP KMS key: {}", seed_envelope.key_id);

        let secret = GcpKms::decrypt_secret(&seed_envelope).await;
        Ok(secret)
    }

    #[cfg(not(feature = "longterm-gcp-kms"))]
    async fn try_load_gcp_kms(&self, _value: &str) -> Result<Secret, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg =
            "GCP KMS is not enabled. Recompile with the 'longterm-gcp-kms' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-aws-secret-manager")]
    async fn try_load_aws_secret_manager(&self, value: &str) -> Result<Secret, StorageError> {
        use crate::longterm::awssecret::AwsSecretManager;
        use crate::longterm::envelope::SecretEnvelope;

        let json_envelope = encoding::try_decode(value)?;
        let seed_envelope = serde_json::from_slice::<SecretEnvelope>(&json_envelope)?;

        let secret_id = seed_envelope
            .key_id
            .strip_prefix(Protection::AwsSecretManager.prefix())
            .unwrap();

        debug!("AWS Secret Manager secret: {}", secret_id);

        let secret = AwsSecretManager::get_secret(secret_id).await;
        Ok(secret)
    }

    #[cfg(not(feature = "longterm-aws-secret-manager"))]
    async fn try_load_aws_secret_manager(&self, _value: &str) -> Result<Secret, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg = "AWS Secret Manager is not enabled. Recompile with the 'longterm-aws-secret-manager' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-aws-secret-manager")]
    async fn try_store_aws_secret_manager(
        &self,
        secret: &Secret,
        resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        use crate::longterm::awssecret::AwsSecretManager;
        use crate::longterm::envelope::SecretEnvelope;

        match AwsSecretManager::store_secret(resource_id, secret).await {
            Err(_) => Err(StorageError::SecretManager(
                "Failed to store seed in AWS Secret Manager".to_string(),
            )),
            Ok(_) => Ok(SecretEnvelope {
                key_id: format!("{}{}", Protection::AwsSecretManager.prefix(), resource_id),
                secret_ct: vec![],
                dek_ct: vec![],
            }),
        }
    }

    #[cfg(not(feature = "longterm-aws-secret-manager"))]
    async fn try_store_aws_secret_manager(
        &self,
        _secret: &Secret,
        _resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg = "AWS Secret Manager is not enabled. Recompile with the 'longterm-aws-secret-manager' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-gcp-secret-manager")]
    async fn try_load_gcp_secret_manager(&self, value: &str) -> Result<Secret, StorageError> {
        use crate::longterm::gcpsecret::GcpSecretManager;

        let json_envelope = encoding::try_decode(value)?;
        let seed_envelope = serde_json::from_slice::<SecretEnvelope>(&json_envelope)?;

        let secret_id = seed_envelope
            .key_id
            .strip_prefix(Protection::GcpSecretManager.prefix())
            .unwrap();

        let secret = GcpSecretManager::get_secret(secret_id).await;
        Ok(secret)
    }

    #[cfg(not(feature = "longterm-gcp-secret-manager"))]
    async fn try_load_gcp_secret_manager(&self, _value: &str) -> Result<Secret, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg = "GCP Secret Manager is not enabled. Recompile with the 'longterm-gcp-secret-manager' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-gcp-secret-manager")]
    async fn try_store_gcp_secret_manager(
        &self,
        secret: &Secret,
        resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        use crate::longterm::envelope::SecretEnvelope;
        use crate::longterm::gcpsecret::GcpSecretManager;

        match GcpSecretManager::store_secret(resource_id, secret).await {
            Err(e) => {
                let msg = format!("Failed to store seed in GCP Secret Manager: {e}");
                Err(StorageError::SecretManager(msg))
            }
            Ok(version) => Ok(SecretEnvelope {
                key_id: format!("{}{}", Protection::GcpSecretManager.prefix(), version),
                secret_ct: vec![],
                dek_ct: vec![],
            }),
        }
    }

    #[cfg(not(feature = "longterm-gcp-secret-manager"))]
    async fn try_store_gcp_secret_manager(
        &self,
        _secret: &Secret,
        _resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg = "GCP Secret Manager is not enabled. Recompile with the 'longterm-gcp-secret-manager' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }

    #[cfg(feature = "longterm-gcp-kms")]
    async fn try_store_gcp_kms(
        &self,
        secret: &Secret,
        resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        use crate::longterm::gcpkms::GcpKms;

        // TODO(stuart) fix the lack of error handling
        Ok(GcpKms::encrypt_secret(resource_id, secret).await)
    }

    #[cfg(not(feature = "longterm-gcp-kms"))]
    async fn try_store_gcp_kms(
        &self,
        _secret: &Secret,
        _resource_id: &str,
    ) -> Result<SecretEnvelope, StorageError> {
        use crate::storage::StorageError::NotImplemented;

        let msg =
            "GCP KMS is not enabled. Recompile with the 'longterm-gcp-kms' feature to support it";
        Err(NotImplemented(msg.to_string()))
    }
}
