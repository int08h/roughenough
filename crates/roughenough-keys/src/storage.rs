use roughenough_common::encoding;
use tracing::{debug, trace};

#[cfg(feature = "longterm-aws")]
use crate::longterm::awskms::AwsKms;
#[cfg(feature = "longterm-aws")]
use crate::longterm::awssecret::AwsSecretManager;
use crate::longterm::envelope::SeedEnvelope;
#[cfg(feature = "longterm-gcp")]
use crate::longterm::gcpkms::GcpKms;
#[cfg(feature = "longterm-gcp")]
use crate::longterm::gcpsecret::GcpSecretManager;
#[cfg(any(feature = "longterm-aws", feature = "longterm-gcp"))]
use crate::runtime::block_on;
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

impl StorageError {
    #[cfg(any(test, feature = "longterm-aws", feature = "longterm-gcp"))]
    pub(crate) fn cloud(backend: &'static str, detail: impl Into<String>) -> Self {
        StorageError::CloudBackend {
            backend,
            detail: detail.into(),
        }
    }
}

/// Decode a hex or base64 seed value
pub fn decode_seed(encoded: &str) -> Result<Seed, StorageError> {
    let bytes = encoding::try_decode(encoded)?;
    Seed::try_from(bytes.as_slice()).map_err(|e| StorageError::InvalidSeed(e.to_string()))
}

/// Loads the seed from secure long-term storage and transfers it to an online backend.
///
/// Blocks; do not call from an async context.
pub fn try_load_seed(value: &str) -> Result<Seed, StorageError> {
    // Never log the value itself: for the seed:// scheme it IS the seed
    trace!("Loading a {}-character seed value", value.len());

    match Protection::split(value) {
        None => {
            debug!("No seed protection prefix, assuming plain text");
            decode_seed(value)
        }
        Some((Protection::Plain, rest)) => decode_seed(rest),
        Some((protection, rest)) => {
            debug!("Seed protection method: {protection:?}");
            let envelope = parse_envelope(rest)?;
            load_envelope(&envelope)
        }
    }
}

/// Protects `seed` with the long-term storage that `resource` names.
///
/// Blocks; do not call from an async context.
pub fn try_store_seed(seed: &Seed, resource: &str) -> Result<SeedEnvelope, StorageError> {
    trace!("Storing seed for {}", resource);

    let Some((protection, rest)) = Protection::split(resource) else {
        return Err(StorageError::InvalidSeed(
            "no protection method specified in resource".to_string(),
        ));
    };
    debug!("Seed protection method: {protection:?}");

    match protection {
        #[cfg(feature = "longterm-aws")]
        Protection::AwsKms => block_on(AwsKms::encrypt_seed(rest, seed)),
        #[cfg(feature = "longterm-gcp")]
        Protection::GcpKms => block_on(GcpKms::encrypt_seed(rest, seed)),
        #[cfg(feature = "longterm-aws")]
        Protection::AwsSecretManager => {
            block_on(AwsSecretManager::store_seed(rest, seed))?;
            Ok(SeedEnvelope {
                key_id: format!("{}{rest}", Protection::AwsSecretManager.prefix()),
                seed_ct: vec![],
                dek_ct: vec![],
            })
        }
        #[cfg(feature = "longterm-gcp")]
        Protection::GcpSecretManager => {
            let version = block_on(GcpSecretManager::store_seed(rest, seed))?;
            Ok(SeedEnvelope {
                key_id: format!("{}{version}", Protection::GcpSecretManager.prefix()),
                seed_ct: vec![],
                dek_ct: vec![],
            })
        }
        Protection::Plain => Err(StorageError::NotImplemented(
            "a 'seed://' value is the seed itself; storing it is a no-op by design".to_string(),
        )),
        #[allow(unreachable_patterns)]
        other => {
            let _ = (seed, rest);
            Err(other.not_enabled())
        }
    }
}

/// Parse the base64-encoded JSON envelope that follows a cloud scheme prefix
pub fn parse_envelope(value: &str) -> Result<SeedEnvelope, StorageError> {
    let json_envelope = encoding::try_decode(value)?;
    Ok(serde_json::from_slice(&json_envelope)?)
}

/// Recover the seed an envelope refers to, dispatching on the scheme in its key id.
///
/// Blocks; do not call from an async context.
pub fn load_envelope(envelope: &SeedEnvelope) -> Result<Seed, StorageError> {
    let (protection, rest) = Protection::split(&envelope.key_id).ok_or_else(|| {
        StorageError::InvalidResource(format!(
            "envelope key id '{}' has no known scheme prefix",
            envelope.key_id
        ))
    })?;

    match protection {
        #[cfg(feature = "longterm-aws")]
        Protection::AwsKms => block_on(AwsKms::decrypt_seed(envelope)),
        #[cfg(feature = "longterm-gcp")]
        Protection::GcpKms => block_on(GcpKms::decrypt_seed(envelope)),
        #[cfg(feature = "longterm-aws")]
        Protection::AwsSecretManager => block_on(AwsSecretManager::get_seed(rest)),
        #[cfg(feature = "longterm-gcp")]
        Protection::GcpSecretManager => block_on(GcpSecretManager::get_seed(rest)),
        Protection::Plain => Err(StorageError::InvalidResource(
            "a seed:// value is not an envelope".to_string(),
        )),
        #[allow(unreachable_patterns)]
        other => {
            let _ = rest;
            Err(other.not_enabled())
        }
    }
}

/// Methods of secure long-term storage for the server's identity.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Protection {
    Plain,
    AwsKms,
    GcpKms,
    AwsSecretManager,
    GcpSecretManager,
}

impl Protection {
    const ALL: [Protection; 5] = [
        Protection::Plain,
        Protection::AwsKms,
        Protection::GcpKms,
        Protection::AwsSecretManager,
        Protection::GcpSecretManager,
    ];

    pub fn prefix(&self) -> &'static str {
        match self {
            Protection::Plain => "seed://",
            Protection::AwsKms => "aws-kms://",
            Protection::GcpKms => "gcp-kms://",
            Protection::AwsSecretManager => "aws-secret://",
            Protection::GcpSecretManager => "gcp-secret://",
        }
    }

    /// Human-readable backend name used in error messages
    #[cfg(any(feature = "longterm-aws", feature = "longterm-gcp"))]
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Protection::Plain => "seed",
            Protection::AwsKms => "AWS KMS",
            Protection::GcpKms => "GCP KMS",
            Protection::AwsSecretManager => "AWS Secret Manager",
            Protection::GcpSecretManager => "GCP Secret Manager",
        }
    }

    /// Split `value` into its protection scheme and the remainder after the prefix
    pub fn split(value: &str) -> Option<(Protection, &str)> {
        Self::ALL
            .iter()
            .find_map(|p| value.strip_prefix(p.prefix()).map(|rest| (*p, rest)))
    }

    /// Encode `envelope` as the single-line prefixed form that `try_load_seed`
    /// accepts, suitable for writing directly to a server seed file.
    pub fn encode_envelope(&self, envelope: &SeedEnvelope) -> Result<String, StorageError> {
        let json = serde_json::to_vec(envelope)?;
        let encoded = data_encoding::BASE64URL.encode(&json);
        Ok(format!("{}{}", self.prefix(), encoded))
    }

    fn feature(&self) -> &'static str {
        match self {
            Protection::Plain => "",
            Protection::AwsKms | Protection::AwsSecretManager => "longterm-aws",
            Protection::GcpKms | Protection::GcpSecretManager => "longterm-gcp",
        }
    }

    fn not_enabled(&self) -> StorageError {
        StorageError::NotImplemented(format!(
            "{self:?} support is not compiled in; rebuild with the '{}' feature",
            self.feature()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheme(value: &str) -> Option<Protection> {
        Protection::split(value).map(|(p, _)| p)
    }

    /// A prefixed seed-file value whose envelope names `key_id`
    #[cfg(not(all(feature = "longterm-aws", feature = "longterm-gcp")))]
    fn encoded_envelope(protection: Protection, key_id: &str) -> String {
        let envelope = SeedEnvelope {
            key_id: key_id.to_string(),
            seed_ct: vec![1, 2, 3],
            dek_ct: vec![4, 5, 6],
        };
        protection.encode_envelope(&envelope).unwrap()
    }

    #[test]
    fn split_routes_every_scheme() {
        assert_eq!(scheme("seed://aabb"), Some(Protection::Plain));
        assert_eq!(
            scheme("aws-kms://arn:aws:kms:us-east-2:1:key/x"),
            Some(Protection::AwsKms)
        );
        assert_eq!(
            scheme("gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k"),
            Some(Protection::GcpKms)
        );
        assert_eq!(
            scheme("aws-secret://arn:aws:secretsmanager:us-east-2:1:secret:x"),
            Some(Protection::AwsSecretManager)
        );
        assert_eq!(
            scheme("gcp-secret://projects/p/secrets/s/versions/1"),
            Some(Protection::GcpSecretManager)
        );

        assert_eq!(scheme("vault://something"), None);
        assert_eq!(scheme("aabbccdd"), None);
        assert_eq!(scheme(""), None);
    }

    #[test]
    fn prefix_round_trips_through_split() {
        for method in Protection::ALL {
            let value = format!("{}whatever", method.prefix());
            assert_eq!(scheme(&value), Some(method));
        }
    }

    #[test]
    fn split_returns_remainder_after_prefix() {
        assert_eq!(
            Protection::split("aws-kms://arn:aws:kms:us-east-2:1:key/x"),
            Some((Protection::AwsKms, "arn:aws:kms:us-east-2:1:key/x"))
        );
        assert_eq!(Protection::split("seed://"), Some((Protection::Plain, "")));
    }

    #[test]
    fn load_envelope_rejects_unknown_scheme() {
        let envelope = SeedEnvelope {
            key_id: "vault://x".to_string(),
            seed_ct: vec![],
            dek_ct: vec![],
        };
        assert!(matches!(
            load_envelope(&envelope),
            Err(StorageError::InvalidResource(_))
        ));
    }

    #[test]
    fn load_envelope_rejects_plain() {
        let envelope = SeedEnvelope {
            key_id: "seed://00".to_string(),
            seed_ct: vec![],
            dek_ct: vec![],
        };
        assert!(matches!(
            load_envelope(&envelope),
            Err(StorageError::InvalidResource(_))
        ));
    }

    #[test]
    fn storing_a_plain_seed_is_an_error_not_a_panic() {
        let seed = Seed::from_bytes(&[7u8; 32]);
        let result = try_store_seed(&seed, "seed://aabbccdd");

        match result {
            Err(StorageError::NotImplemented(msg)) => {
                assert!(msg.contains("no-op by design"), "unexpected: {msg}")
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn storing_with_unknown_scheme_is_an_error() {
        let seed = Seed::from_bytes(&[7u8; 32]);
        let result = try_store_seed(&seed, "vault://something");
        assert!(matches!(result, Err(StorageError::InvalidSeed(_))));
    }

    #[test]
    fn plain_seed_loads_from_hex() {
        let value = format!("seed://{}", "aa".repeat(32));
        let seed = try_load_seed(&value).unwrap();
        assert_eq!(seed.expose(), &[0xaa; 32]);

        // No prefix falls back to plain
        let seed = try_load_seed(&"bb".repeat(32)).unwrap();
        assert_eq!(seed.expose(), &[0xbb; 32]);
    }

    #[test]
    fn plain_seed_with_wrong_length_is_an_error() {
        let result = try_load_seed("seed://aabbcc");
        assert!(matches!(result, Err(StorageError::InvalidSeed(_))));
    }

    #[cfg(not(feature = "longterm-aws"))]
    #[test]
    fn try_load_seed_with_disabled_feature_names_the_feature() {
        let value = encoded_envelope(
            Protection::AwsKms,
            "aws-kms://arn:aws:kms:us-east-2:1:key/x",
        );
        match try_load_seed(&value) {
            Err(StorageError::NotImplemented(msg)) => {
                assert!(msg.contains("longterm-aws"), "unexpected: {msg}")
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[cfg(not(feature = "longterm-aws"))]
    #[test]
    fn aws_without_feature_is_not_implemented() {
        let seed = Seed::from_bytes(&[7u8; 32]);
        for (protection, key_id) in [
            (
                Protection::AwsKms,
                "aws-kms://arn:aws:kms:us-east-2:1:key/x",
            ),
            (
                Protection::AwsSecretManager,
                "aws-secret://arn:aws:secretsmanager:us-east-2:1:secret:x",
            ),
        ] {
            let value = encoded_envelope(protection, key_id);
            let load = try_load_seed(&value);
            assert!(matches!(load, Err(StorageError::NotImplemented(_))));
            let store = try_store_seed(&seed, key_id);
            assert!(matches!(store, Err(StorageError::NotImplemented(_))));
        }
    }

    #[cfg(not(feature = "longterm-gcp"))]
    #[test]
    fn gcp_without_feature_is_not_implemented() {
        let seed = Seed::from_bytes(&[7u8; 32]);
        for (protection, key_id) in [
            (
                Protection::GcpKms,
                "gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k",
            ),
            (
                Protection::GcpSecretManager,
                "gcp-secret://projects/p/secrets/s/versions/1",
            ),
        ] {
            let value = encoded_envelope(protection, key_id);
            let load = try_load_seed(&value);
            assert!(matches!(load, Err(StorageError::NotImplemented(_))));
            let store = try_store_seed(&seed, key_id);
            assert!(matches!(store, Err(StorageError::NotImplemented(_))));
        }
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
        let (protection, value) = Protection::split(&encoded).unwrap();
        assert_eq!(protection, Protection::AwsSecretManager);

        // And the value after the prefix decodes back to the same envelope
        let parsed = parse_envelope(value).unwrap();
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
        let (protection, value) = Protection::split(&encoded).unwrap();
        assert_eq!(protection, Protection::AwsKms);

        let parsed = parse_envelope(value).unwrap();
        assert_eq!(parsed.key_id, envelope.key_id);
        assert_eq!(parsed.seed_ct, envelope.seed_ct);
        assert_eq!(parsed.dek_ct, envelope.dek_ct);
    }

    #[test]
    fn storage_error_display_formats() {
        let err = StorageError::cloud("AWS KMS", "call failed");
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
