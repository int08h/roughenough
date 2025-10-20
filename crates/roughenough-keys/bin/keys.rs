//! Key management operations

use std::io::ErrorKind;

use clap::Parser;
#[cfg(feature = "longterm-aws-kms")]
use roughenough_keys::longterm::awskms;
use roughenough_keys::longterm::envelope::SeedEnvelope;
#[cfg(feature = "longterm-gcp-kms")]
use roughenough_keys::longterm::gcpkms;
use roughenough_keys::seed::Seed;
use roughenough_keys::storage;
use roughenough_protocol::util::as_hex;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Error};
use tracing::{debug, error};

#[derive(clap::Parser, Debug)]
#[command(version = "2.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[clap(
        short = 'v',
        long,
        action = clap::ArgAction::Count,
        help = "Output details; specify multiple times for more detail"
    )]
    pub verbose: u8,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Generate a new random long-term identity seed
    Generate {
        #[clap(
            short,
            long,
            conflicts_with = "secret",
            help = "Output file for generated long-term identity seed"
        )]
        output: Option<String>,
        #[clap(
            short,
            long,
            conflicts_with = "secret",
            help = "Key ID to envelope encrypt the seed with"
        )]
        key: Option<String>,
        #[clap(
            short,
            long,
            conflicts_with = "output",
            help = "Secret ID to store generated seed in"
        )]
        secret: Option<String>,
    },
    /// Envelope encrypt a long-term identity seed
    Seal {
        #[clap(short, long, help = "File or data of long-term identity seed")]
        input: String,
        #[clap(short, long, help = "Output file for envelope encrypted seed")]
        output: Option<String>,
        #[clap(short, long, help = "Key ID to use for envelope encryption")]
        key: String,
    },
    /// Decrypt an envelope encrypted long-term identity seed
    Open {
        #[clap(
            short,
            long,
            help = "File or data of envelope encrypted long-term identity seed"
        )]
        input: String,
        #[clap(
            short,
            long,
            help = "Output file for decrypted long-term identity seed"
        )]
        output: Option<String>,
        #[clap(
            short,
            long,
            help = "Override the key ID in data blob and use this key ID for decryption"
        )]
        key: Option<String>,
    },
    /// Store a long-term identity seed in a Secret manager
    Store {
        #[clap(short, long, help = "File or data of long-term identity seed")]
        input: String,
        #[clap(short, long, help = "Output file for json encoded storage envelope")]
        output: Option<String>,
        #[clap(short, long, help = "Secret ID to store seed in")]
        secret: String,
    },
    /// Retrieve a long-term identity seed from a Secret manager
    Get {
        #[clap(
            short,
            long,
            help = "File or data of previously store'ed long-term identity seed"
        )]
        input: String,
        #[clap(
            short,
            long,
            help = "Output file for decrypted long-term identity seed"
        )]
        output: Option<String>,
    },
}

type OutFile = Box<dyn AsyncWrite + Unpin>;
type InFile = Box<dyn AsyncRead + Unpin>;

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    enable_logging(&cli);

    match cli.command {
        Commands::Generate {
            output,
            key,
            secret,
        } => {
            let output = outfile_from_arg(output).await.unwrap();
            handle_generate(output, key, secret).await;
        }

        Commands::Seal { input, output, key } => {
            let input = infile_from_arg(Some(input)).await.unwrap();
            let output = outfile_from_arg(output).await.unwrap();
            handle_seal(input, output, key).await;
        }

        Commands::Open { input, output, key } => {
            let input = infile_from_arg(Some(input)).await.unwrap();
            let output = outfile_from_arg(output).await.unwrap();
            handle_open(input, output, key).await;
        }

        Commands::Store {
            input,
            output,
            secret,
        } => {
            let input = infile_from_arg(Some(input)).await.unwrap();
            let output = outfile_from_arg(output).await.unwrap();
            handle_store(input, output, secret).await;
        }

        Commands::Get { input, output } => {
            let input = infile_from_arg(Some(input)).await.unwrap();
            let output = outfile_from_arg(output).await.unwrap();
            handle_get(input, output).await;
        }
    }
}

async fn handle_generate(mut output: OutFile, key: Option<String>, secret: Option<String>) {
    if !(key.is_some() || secret.is_some()) {
        error!("Either --key or --secret must be specified");
        return;
    }

    let resource = key.or(secret).unwrap();
    let seed = Seed::new_random();

    match storage::try_store_seed(&seed, &resource).await {
        Ok(envelope) => {
            let json = serde_json::to_string_pretty(&envelope).unwrap();
            output.write_all(json.as_bytes()).await.unwrap();
        }
        Err(e) => {
            error!("Failed to store seed: {:?}", e);
        }
    }
}

/// Retrieve a long-term identity seed from a Secret manager
async fn handle_get(mut input: InFile, mut output: OutFile) {
    let mut value = String::new();
    input.read_to_string(&mut value).await.unwrap();

    match storage::try_load_seed(&value).await {
        Ok(seed) => {
            let encoded = as_hex(seed.expose());
            output.write_all(encoded.as_bytes()).await.unwrap();
            output.write_all(b"\n").await.unwrap();
        }
        Err(e) => {
            error!("Failed to retrieve seed: {:?}", e);
        }
    }
}

/// Store a long-term identity seed in a Secret manager
async fn handle_store(mut input: InFile, mut output: OutFile, secret: String) {
    let mut seed_bytes = Vec::new();
    input.read_to_end(&mut seed_bytes).await.unwrap();

    if seed_bytes.len() != 32 {
        error!(
            "Invalid seed length: expected 32 bytes, got {}",
            seed_bytes.len()
        );
        return;
    }

    let seed = Seed::new(&seed_bytes);

    // TODO(stuart) need to encode this output into a format that can be read:
    //    aws-secret://...HEX ENCODED JSON...
    // awkward, but it will work
    match storage::try_store_seed(&seed, &secret).await {
        Ok(envelope) => {
            let json = serde_json::to_string_pretty(&envelope).unwrap();
            output.write_all(json.as_bytes()).await.unwrap();
            output.write_all(b"\n").await.unwrap();
        }
        Err(e) => {
            error!("Failed to store seed: {:?}", e);
        }
    }
}

/// Decrypt an envelope encrypted long-term identity seed
async fn handle_open(mut input: InFile, mut output: OutFile, key: Option<String>) {
    let mut buf = Vec::new();
    input.read_to_end(&mut buf).await.unwrap();
    let mut envelope: SeedEnvelope = serde_json::from_slice(&buf).unwrap();

    if let Some(key_id) = key {
        debug!(
            "Overriding original key ID {} with {}",
            envelope.key_id, key_id
        );
        envelope.key_id = key_id;
    }

    // Below is ugly to deal with conditional compilation while keeping the
    // compiler and clippy happy

    #[allow(unused_mut)]
    let mut seed: Seed = Seed::new_random();

    #[cfg(feature = "longterm-gcp-kms")]
    {
        use crate::storage::Protection;
        if envelope.key_id.starts_with(Protection::GcpKms.prefix()) {
            seed = gcpkms::GcpKms::decrypt_seed(&envelope).await
        }
    }

    #[cfg(feature = "longterm-aws-kms")]
    {
        use crate::storage::Protection;
        if envelope.key_id.starts_with(Protection::AwsKms.prefix()) {
            seed = awskms::AwsKms::decrypt_seed(&envelope).await
        }
    }

    if cfg!(not(any(
        feature = "longterm-gcp-kms",
        feature = "longterm-aws-kms"
    ))) {
        error!("no KMS types enabled: {}", envelope.key_id);
        return;
    };

    let encoded = as_hex(seed.expose());
    output.write_all(encoded.as_bytes()).await.unwrap();
    output.write_all(b"\n").await.unwrap();
}

/// Envelope encrypt a long-term identity seed
async fn handle_seal(mut input: InFile, mut output: OutFile, key: String) {
    let mut seed_bytes = Vec::new();
    input.read_to_end(&mut seed_bytes).await.unwrap();

    if seed_bytes.len() != 32 {
        error!(
            "Invalid seed length: expected 32 bytes, got {}",
            seed_bytes.len()
        );
        return;
    }

    let seed = Seed::new(&seed_bytes);

    match storage::try_store_seed(&seed, &key).await {
        Ok(envelope) => {
            let json = serde_json::to_string_pretty(&envelope).unwrap();
            output.write_all(json.as_bytes()).await.unwrap();
        }
        Err(e) => {
            error!("Failed to encrypt seed: {:?}", e);
        }
    }
}

async fn outfile_from_arg(path: Option<String>) -> tokio::io::Result<OutFile> {
    match path {
        Some(file_path) => {
            let file = match File::create_new(&file_path).await {
                Ok(file) => file,
                Err(e) => {
                    error!("Failed to create output file '{}': {:?}", &file_path, e);
                    return Err(e);
                }
            };
            Ok(Box::new(file))
        }
        None => Ok(Box::new(tokio::io::stdout())),
    }
}

// make non optional
async fn infile_from_arg(path: Option<String>) -> tokio::io::Result<InFile> {
    match path {
        Some(file_path) => {
            let file = File::open(file_path).await?;
            Ok(Box::new(file))
        }
        None => Err(Error::new(
            ErrorKind::InvalidInput,
            "no input file specified",
        )),
    }
}

fn enable_logging(cli: &Cli) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{Layer, filter};

    // AWS, GCP, Rustls, Hyper, etc crates are quite verbose, "normal" level for them is WARN
    let cloud_sdk_verbosity = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        3.. => tracing::Level::TRACE,
    };

    let verbosity = match cli.verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        2.. => tracing::Level::TRACE,
    };

    let filters = filter::Targets::new()
        .with_target("aws_config", cloud_sdk_verbosity)
        .with_target("aws_sdk_kms", cloud_sdk_verbosity)
        .with_target("aws_sdk_secretsmanager", cloud_sdk_verbosity)
        .with_target("google_cloud_kms_v1", cloud_sdk_verbosity)
        .with_target("google_cloud_secretmanager_v1", cloud_sdk_verbosity)
        .with_target("hyper_util", cloud_sdk_verbosity)
        .with_target("rustls", cloud_sdk_verbosity)
        .with_default(verbosity); // for all other targets

    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_filter(filters);

    tracing_subscriber::registry().with(fmt_layer).init();
}
