use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Roughenough roughtime server")]
pub struct Args {
    /// The maximum number of requests to process in one batch
    #[clap(
        short = 'b',
        long,
        value_name = "N",
        env = "ROUGHENOUGH_BATCH_SIZE",
        default_value_t = 64,
        value_parser = clap::value_parser!(u8).range(1..=64)
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

    /// Port to listen on
    #[clap(short = 'p', long, env = "ROUGHENOUGH_PORT", default_value = "2003")]
    pub port: u16,

    /// Number of worker threads to process requests in parallel
    #[clap(
        short = 'j',
        long,
        value_name = "N",
        env = "ROUGHENOUGH_NUM_THREADS",
        default_value_t = default_num_threads()
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
        default_value = "24"
    )]
    pub rotation_interval: u16,

    /// How often (in seconds) to log operational information
    #[clap(
        long,
        value_name = "SECONDS",
        env = "ROUGHENOUGH_METRICS_INTERVAL",
        default_value = "60"
    )]
    pub metrics_interval: u64,

    /// Secret value for the server's long-term identity
    #[clap(
        long,
        value_name = "SEED",
        env = "ROUGHENOUGH_SEED",
        default_value = ""
    )]
    pub seed: String,

    /// For testing only; never use in production.
    #[clap(long, default_value_t = false)]
    pub insecure_zero_seed: bool,

    /// How to store the server's long-term identity while it's running
    #[clap(
        value_enum,
        long,
        value_name = "TYPE",
        env = "ROUGHENOUGH_SEED_BACKEND",
        default_value_t = SeedBackendArg::Memory
    )]
    pub seed_backend: SeedBackendArg,

    /// Directory path where metrics JSON files will be written
    #[clap(
        long,
        value_name = "PATH",
        env = "ROUGHENOUGH_METRICS_OUTPUT",
        help = "Directory where JSON metrics files will be written (e.g., /var/log/roughenough)"
    )]
    pub metrics_output: Option<String>,

    #[clap(
        short = 'v',
        long,
        conflicts_with = "quiet",
        action = clap::ArgAction::Count,
        help = "Output details about requests and responses; specify multiple times for more detail"
    )]
    pub verbose: u8,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum SeedBackendArg {
    #[value(name = "memory")]
    Memory,
    #[value(name = "krs")]
    Krs,
    #[value(name = "ssh-agent")]
    SshAgent,
    #[value(name = "pkcs11")]
    Pkcs11,
}

impl Display for SeedBackendArg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = self.to_possible_value().unwrap();
        f.write_str(value.get_name())
    }
}

impl Args {
    pub fn udp_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.interface, self.port)
    }

    /// How long the short-term response signing key is valid
    pub fn rotation_interval(&self) -> Duration {
        Duration::from_secs(self.rotation_interval as u64 * 60 * 60)
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
        let args = Args::try_parse_from(["roughenough_server"]).unwrap();
        assert!(!args.insecure_zero_seed);
        assert_eq!(args.udp_socket_addr(), "0.0.0.0:2003".parse().unwrap());
    }

    #[test]
    fn ipv4_and_ipv6_interfaces_parse() {
        let args = Args::try_parse_from(["prog", "-i", "127.0.0.1"]).unwrap();
        assert_eq!(args.udp_socket_addr(), "127.0.0.1:2003".parse().unwrap());

        let args = Args::try_parse_from(["prog", "-i", "::1", "-p", "9999"]).unwrap();
        assert_eq!(args.udp_socket_addr(), "[::1]:9999".parse().unwrap());
    }

    #[test]
    fn non_ip_interface_is_rejected() {
        assert!(Args::try_parse_from(["prog", "-i", "eth0"]).is_err());
        assert!(Args::try_parse_from(["prog", "-i", "not-an-ip"]).is_err());
    }

    #[test]
    fn version_output_matches_crate_version() {
        let err = Args::try_parse_from(["prog", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn rotation_interval_converts_hours_to_seconds() {
        let args = Args::try_parse_from(["prog", "--rotation-interval", "1"]).unwrap();
        assert_eq!(args.rotation_interval(), Duration::from_secs(3600));

        let args = Args::try_parse_from(["prog", "--rotation-interval", "65535"]).unwrap();
        assert_eq!(args.rotation_interval(), Duration::from_secs(65535 * 3600));
    }
}
