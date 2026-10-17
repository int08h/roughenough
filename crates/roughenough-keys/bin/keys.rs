//! Key management operations

use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use roughenough_keys::logging;
use roughenough_keys::longterm::envelope::SeedEnvelope;
use roughenough_keys::seed::Seed;
use roughenough_keys::storage::{self, Protection, StorageError};
use tracing::{debug, error};
use zeroize::Zeroizing;

const RESOURCE_HELP: &str = "Where to protect the seed: aws-kms://<key ARN>, gcp-kms://<key name>, \
                             aws-secret://<secret ARN>, or gcp-secret://<secret name>";

#[derive(clap::Parser, Debug)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[clap(
        short = 'v',
        long,
        global = true,
        action = clap::ArgAction::Count,
        help = "Output details; specify multiple times for more detail"
    )]
    verbose: u8,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Generate a random long-term identity seed and protect it
    Generate {
        #[clap(long, help = RESOURCE_HELP)]
        resource: String,
        #[clap(
            short,
            long,
            help = "Write the protected seed file to this new file instead of stdout"
        )]
        output: Option<PathBuf>,
        #[clap(
            long,
            help = "Print pretty JSON instead of the one-line seed file form"
        )]
        json: bool,
    },
    /// Protect the long-term identity seed in an existing seed file
    Protect {
        #[clap(
            short,
            long,
            help = "Seed file to protect, in any form the server's --seed-file accepts"
        )]
        input: PathBuf,
        #[clap(long, help = RESOURCE_HELP)]
        resource: String,
        #[clap(
            short,
            long,
            help = "Write the protected seed file to this new file instead of stdout"
        )]
        output: Option<PathBuf>,
        #[clap(
            long,
            help = "Print pretty JSON instead of the one-line seed file form"
        )]
        json: bool,
    },
    /// Recover the plain long-term identity seed from a protected seed file or JSON envelope
    Recover {
        #[clap(short, long, help = "Protected seed file or JSON envelope")]
        input: PathBuf,
        #[clap(
            short,
            long,
            help = "Decrypt with this key id instead of the envelope's; an id without a scheme \
                    prefix keeps the envelope's scheme"
        )]
        key: Option<String>,
        #[clap(
            short,
            long,
            help = "Write the seed to this new file instead of stdout"
        )]
        output: Option<PathBuf>,
    },
}

impl Commands {
    fn output(&self) -> Option<&Path> {
        match self {
            Commands::Generate { output, .. }
            | Commands::Protect { output, .. }
            | Commands::Recover { output, .. } => output.as_deref(),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    enable_logging(cli.verbose);

    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Commands) -> Result<(), Box<dyn Error>> {
    // Created before any cloud call, so an existing file fails fast instead of after a
    // secret manager has already stored a new seed
    let output_path = command.output().map(Path::to_path_buf);
    let mut output = outfile_from_arg(output_path.as_deref())
        .map_err(|e| with_path(output_path.as_deref(), e))?;

    let result = match command {
        Commands::Generate { resource, json, .. } => generate(&resource, json),
        Commands::Protect {
            input,
            resource,
            json,
            ..
        } => protect(&input, &resource, json),
        Commands::Recover { input, key, .. } => recover(&input, key.as_deref()),
    }
    .and_then(|text| {
        output.write_all(text.as_bytes())?;
        output.flush()?;
        Ok(())
    });

    // Leave no empty or partial file behind to trip up a retry
    if result.is_err() {
        drop(output);
        if let Some(path) = &output_path {
            let _ = std::fs::remove_file(path);
        }
    }

    result
}

fn generate(resource: &str, json: bool) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let seed = Seed::new_random();
    let envelope = storage::try_store_seed(&seed, resource)?;
    format_envelope(&envelope, json)
}

fn protect(input: &Path, resource: &str, json: bool) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let seed = storage::load_seed_file(input).map_err(|e| with_path(Some(input), e))?;
    let envelope = storage::try_store_seed(&seed, resource)?;
    format_envelope(&envelope, json)
}

fn recover(input: &Path, key: Option<&str>) -> Result<Zeroizing<String>, Box<dyn Error>> {
    // Usually a non-secret envelope, but a seed:// file holds the seed itself
    let contents = std::fs::read_to_string(input).map_err(|e| with_path(Some(input), e))?;
    let contents = Zeroizing::new(contents);
    let text = contents.trim();

    let seed = if text.starts_with('{') {
        let envelope: SeedEnvelope = serde_json::from_str(text)?;
        load_envelope(envelope, key)?
    } else {
        match Protection::split(text) {
            None | Some((Protection::Plain, _)) => {
                if key.is_some() {
                    return Err("--key applies only to an envelope, not a plain seed".into());
                }
                storage::try_load_seed(text)?
            }
            Some((_, rest)) => {
                let envelope = storage::parse_envelope(rest)?;
                load_envelope(envelope, key)?
            }
        }
    };

    // Sized up front so the encoder never reallocates and leaves a copy in freed memory
    let prefix = Protection::Plain.prefix();
    let mut line = Zeroizing::new(String::with_capacity(prefix.len() + 2 * Seed::LEN + 1));
    line.push_str(prefix);
    data_encoding::HEXLOWER.encode_append(seed.expose(), &mut line);
    line.push('\n');
    Ok(line)
}

fn load_envelope(mut envelope: SeedEnvelope, key: Option<&str>) -> Result<Seed, StorageError> {
    if let Some(key) = key {
        let key_id = override_key_id(&envelope.key_id, key);
        debug!(
            "Overriding envelope key id {} with {key_id}",
            envelope.key_id
        );
        envelope.key_id = key_id;
    }
    storage::load_envelope(&envelope)
}

/// A bare key id, such as an ARN, is the natural thing to type; give it the envelope's scheme
/// so it routes to the backend that made the envelope
fn override_key_id(envelope_key_id: &str, key: &str) -> String {
    if Protection::split(key).is_some() {
        return key.to_string();
    }
    match Protection::split(envelope_key_id) {
        Some((protection, _)) => format!("{}{key}", protection.prefix()),
        None => key.to_string(),
    }
}

/// The default one-line form is what the server's `--seed-file` loads
fn format_envelope(
    envelope: &SeedEnvelope,
    json: bool,
) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let mut text = if json {
        serde_json::to_string_pretty(envelope)?
    } else {
        let (protection, _) = Protection::split(&envelope.key_id).ok_or_else(|| {
            format!(
                "envelope key id '{}' has no known scheme prefix",
                envelope.key_id
            )
        })?;
        protection.encode_envelope(envelope)?
    };
    text.push('\n');
    Ok(Zeroizing::new(text))
}

fn with_path(path: Option<&Path>, e: impl std::fmt::Display) -> String {
    match path {
        Some(path) => format!("{}: {e}", path.display()),
        None => e.to_string(),
    }
}

fn outfile_from_arg(path: Option<&Path>) -> std::io::Result<Box<dyn Write>> {
    let Some(path) = path else {
        return Ok(Box::new(std::io::stdout()));
    };

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    let file = options.open(path)?;
    Ok(Box::new(file))
}

fn enable_logging(verbose: u8) {
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // AWS, GCP, Rustls, Hyper, etc crates are quite verbose, "normal" level for them is WARN
    let cloud_sdk_verbosity = match verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        3.. => tracing::Level::TRACE,
    };

    let verbosity = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        2.. => tracing::Level::TRACE,
    };

    // Stdout carries only seeds and seed files, so it can be redirected straight to a file
    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_writer(std::io::stderr)
        .with_filter(logging::sdk_targets(cloud_sdk_verbosity, verbosity));

    tracing_subscriber::registry().with(fmt_layer).init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_output_matches_crate_version() {
        let err = Cli::try_parse_from(["prog", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[cfg(unix)]
    #[test]
    fn output_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "roughenough-keys-output-mode-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let output = outfile_from_arg(Some(&path)).unwrap();
        drop(output);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn key_override_keeps_scheme_prefix() {
        let envelope_key = "aws-kms://arn:aws:kms:us-east-1:1:key/old";

        assert_eq!(
            override_key_id(envelope_key, "arn:aws:kms:us-east-1:1:key/new"),
            "aws-kms://arn:aws:kms:us-east-1:1:key/new"
        );
        assert_eq!(
            override_key_id(
                envelope_key,
                "gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k"
            ),
            "gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k"
        );
        assert_eq!(override_key_id("vault://x", "bare"), "bare");
    }

    #[test]
    fn default_output_is_a_seed_file_value() {
        let envelope = SeedEnvelope {
            key_id: "aws-kms://arn:aws:kms:us-east-1:1:key/x".to_string(),
            seed_ct: vec![1, 2, 3],
            dek_ct: vec![4, 5, 6],
        };

        let text = format_envelope(&envelope, false).unwrap();
        let line = text.strip_suffix('\n').unwrap();
        assert!(!line.contains('\n'));

        let (protection, rest) = Protection::split(line).unwrap();
        assert_eq!(protection, Protection::AwsKms);
        let parsed = storage::parse_envelope(rest).unwrap();
        assert_eq!(parsed.key_id, envelope.key_id);
        assert_eq!(parsed.seed_ct, envelope.seed_ct);
        assert_eq!(parsed.dek_ct, envelope.dek_ct);
    }
}
