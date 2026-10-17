use tracing::Level;
use tracing_subscriber::filter::Targets;

/// Cloud SDK and HTTP stacks are noisy; callers give them their own level
pub fn sdk_targets(sdk_level: Level, default_level: Level) -> Targets {
    Targets::new()
        .with_target("aws_config", sdk_level)
        .with_target("aws_sdk_kms", sdk_level)
        .with_target("aws_sdk_secretsmanager", sdk_level)
        .with_target("google_cloud_kms_v1", sdk_level)
        .with_target("google_cloud_secretmanager_v1", sdk_level)
        .with_target("hyper_util", sdk_level)
        .with_target("rustls", sdk_level)
        .with_default(default_level)
}
