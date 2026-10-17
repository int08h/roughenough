use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use roughenough_keys::seed::BackendKind;

use crate::MAX_BATCH_SIZE;

#[derive(Parser, Debug)]
#[command(version, about = "Roughenough roughtime server")]
pub struct Args {
    /// The maximum number of requests to process in one batch
    #[clap(
        short = 'b',
        long,
        value_name = "N",
        env = "ROUGHENOUGH_BATCH_SIZE",
        default_value_t = MAX_BATCH_SIZE as u8,
        value_parser = clap::value_parser!(u8).range(1..=MAX_BATCH_SIZE as i64)
    )]
    pub batch_size: u8,

    /// IP address to listen on
    #[clap(
        short = 'i',
        long,
        env = "ROUGHENOUGH_INTERFACE",
        default_value = "0.0.0.0"
    )]
    pub interface: IpAddr,

    /// Port to listen on (RFC 12.1: IANA assigned 5319 to Roughtime)
    #[clap(short = 'p', long, env = "ROUGHENOUGH_PORT", default_value = "5319")]
    pub port: u16,

    /// Number of worker threads to process requests in parallel
    #[clap(
        short = 'j',
        long,
        value_name = "N",
        env = "ROUGHENOUGH_NUM_THREADS",
        default_value_t = default_num_threads(),
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub num_threads: u16,

    /// Number of seconds to add/subtract from the wall clock time; for testing
    #[clap(
        long,
        value_name = "N",
        env = "ROUGHENOUGH_FIXED_OFFSET",
        default_value_t = 0
    )]
    pub fixed_offset: i16,

    /// Keep quiet and only log errors
    #[clap(short, long, conflicts_with = "verbose", default_value_t = false)]
    pub quiet: bool,

    /// How often (in hours) the short-term signing key is rotated (regenerated)
    #[clap(
        long,
        value_name = "HOURS",
        env = "ROUGHENOUGH_ROTATION_INTERVAL",
        default_value = "24",
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub rotation_interval: u16,

    /// How often (in seconds, at most one day) to log operational information
    #[clap(
        long,
        value_name = "SECONDS",
        env = "ROUGHENOUGH_METRICS_INTERVAL",
        default_value = "60",
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    pub metrics_interval: u64,

    /// File containing the server's long-term identity seed or protected seed reference
    #[clap(
        long,
        value_name = "PATH",
        env = "ROUGHENOUGH_SEED_FILE",
        conflicts_with = "insecure_zero_seed"
    )]
    pub seed_file: Option<PathBuf>,

    /// For testing only; never use in production.
    #[clap(long, default_value_t = false)]
    pub insecure_zero_seed: bool,

    /// How to store the server's long-term identity while it's running
    #[clap(
        value_enum,
        long,
        value_name = "TYPE",
        env = "ROUGHENOUGH_SEED_BACKEND",
        default_value_t = BackendKind::Memory
    )]
    pub seed_backend: BackendKind,

    /// Directory where JSON metrics files will be written (e.g., /var/log/roughenough)
    #[clap(long, value_name = "PATH", env = "ROUGHENOUGH_METRICS_OUTPUT")]
    pub metrics_output: Option<PathBuf>,

    /// Output details about requests and responses; specify multiple times for more detail
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

impl Args {
    pub fn udp_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.interface, self.port)
    }

    /// How long the short-term response signing key is valid
    pub fn rotation_interval(&self) -> Duration {
        Duration::from_secs(self.rotation_interval as u64 * 60 * 60)
    }

    /// A pkcs11 token holds the long-term key itself, so it takes no seed; every other backend
    /// needs one. clap cannot express "required unless --seed-backend is pkcs11" declaratively.
    pub fn validate_seed_source(&self) -> Result<(), clap::Error> {
        let has_seed = self.seed_file.is_some() || self.insecure_zero_seed;
        match (self.seed_backend.takes_seed(), has_seed) {
            (true, false) => Err(Args::command().error(
                ErrorKind::MissingRequiredArgument,
                "a seed is required: pass --seed-file <PATH> (or --insecure-zero-seed for testing)",
            )),
            (false, true) => Err(Args::command().error(
                ErrorKind::ArgumentConflict,
                format!(
                    "--seed-file and --insecure-zero-seed are not used with --seed-backend {}; the token holds the long-term key",
                    self.seed_backend
                ),
            )),
            _ => Ok(()),
        }
    }
}

fn default_num_threads() -> u16 {
    std::thread::available_parallelism().unwrap().get() as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_args_parse() {
        let args = Args::try_parse_from(["roughenough_server", "--insecure-zero-seed"]).unwrap();
        assert!(args.insecure_zero_seed);
        assert_eq!(args.udp_socket_addr(), "0.0.0.0:5319".parse().unwrap());
    }

    #[test]
    fn ipv4_and_ipv6_interfaces_parse() {
        let args =
            Args::try_parse_from(["prog", "--insecure-zero-seed", "-i", "127.0.0.1"]).unwrap();
        assert_eq!(args.udp_socket_addr(), "127.0.0.1:5319".parse().unwrap());

        let args =
            Args::try_parse_from(["prog", "--insecure-zero-seed", "-i", "::1", "-p", "9999"])
                .unwrap();
        assert_eq!(args.udp_socket_addr(), "[::1]:9999".parse().unwrap());
    }

    #[test]
    fn non_ip_interface_is_rejected() {
        assert!(Args::try_parse_from(["prog", "--insecure-zero-seed", "-i", "eth0"]).is_err());
        assert!(Args::try_parse_from(["prog", "--insecure-zero-seed", "-i", "not-an-ip"]).is_err());
    }

    #[test]
    fn version_output_matches_crate_version() {
        let err = Args::try_parse_from(["prog", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn rotation_interval_converts_hours_to_seconds() {
        let args =
            Args::try_parse_from(["prog", "--insecure-zero-seed", "--rotation-interval", "1"])
                .unwrap();
        assert_eq!(args.rotation_interval(), Duration::from_secs(3600));

        let args = Args::try_parse_from([
            "prog",
            "--insecure-zero-seed",
            "--rotation-interval",
            "65535",
        ])
        .unwrap();
        assert_eq!(args.rotation_interval(), Duration::from_secs(65535 * 3600));
    }

    #[test]
    fn out_of_range_intervals_and_thread_counts_are_rejected() {
        for bad in [
            ["--num-threads", "0"],
            ["--rotation-interval", "0"],
            ["--metrics-interval", "0"],
            ["--metrics-interval", "86401"],
        ] {
            let mut argv = vec!["prog", "--insecure-zero-seed"];
            argv.extend(bad);
            assert!(Args::try_parse_from(&argv).is_err(), "{bad:?} accepted");
        }

        let args = Args::try_parse_from([
            "prog",
            "--insecure-zero-seed",
            "--num-threads",
            "1",
            "--metrics-interval",
            "86400",
        ])
        .unwrap();
        assert_eq!(args.num_threads, 1);
        assert_eq!(args.metrics_interval, 86_400);
    }

    #[test]
    fn seed_file_and_insecure_seed_are_mutually_exclusive() {
        assert!(
            Args::try_parse_from(["prog", "--seed-file", "/tmp/seed", "--insecure-zero-seed",])
                .is_err()
        );
    }

    #[test]
    fn quiet_and_verbose_conflict() {
        assert!(Args::try_parse_from(["prog", "--insecure-zero-seed", "-q", "-v"]).is_err());
    }

    #[test]
    fn seed_source_is_required_unless_pkcs11() {
        let args = Args::try_parse_from(["prog"]).unwrap();
        let err = args.validate_seed_source().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--seed-file"), "{err}");

        let args = Args::try_parse_from(["prog", "--seed-backend", "pkcs11"]).unwrap();
        assert!(args.validate_seed_source().is_ok());

        for seed_source in [
            &["--insecure-zero-seed"][..],
            &["--seed-file", "/tmp/seed"][..],
        ] {
            let mut argv = vec!["prog", "--seed-backend", "pkcs11"];
            argv.extend(seed_source);
            let args = Args::try_parse_from(&argv).unwrap();
            assert_eq!(args.seed_backend, BackendKind::Pkcs11);
            assert_eq!(
                args.validate_seed_source().unwrap_err().kind(),
                ErrorKind::ArgumentConflict,
                "{seed_source:?}"
            );
        }
    }

    #[test]
    fn seed_backend_names_and_alias_parse() {
        let args = Args::try_parse_from(["prog", "--insecure-zero-seed"]).unwrap();
        assert_eq!(args.seed_backend, BackendKind::Memory);

        for (name, kind) in [
            ("memory", BackendKind::Memory),
            ("krs", BackendKind::Krs),
            ("ssh-agent", BackendKind::SshAgent),
            ("sshagent", BackendKind::SshAgent),
            ("pkcs11", BackendKind::Pkcs11),
        ] {
            let args =
                Args::try_parse_from(["prog", "--insecure-zero-seed", "--seed-backend", name])
                    .unwrap();
            assert_eq!(args.seed_backend, kind, "{name}");
        }

        assert!(
            Args::try_parse_from(["prog", "--insecure-zero-seed", "--seed-backend", "tpm"])
                .is_err()
        );
    }

    #[test]
    fn direct_seed_argument_is_rejected() {
        assert!(Args::try_parse_from(["prog", "--seed", "secret"]).is_err());
    }
}
