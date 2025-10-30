use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use roughenough_protocol::tags::Version;

#[derive(Parser, Debug, Clone)]
#[command(version = "2.0.0", about = "Roughenough roughtime server")]
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

    /// IP address or interface name to listen on
    #[clap(
        short = 'i',
        long,
        env = "ROUGHENOUGH_INTERFACE",
        default_value = "0.0.0.0"
    )]
    pub interface: String,

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

    /// Version of the protocol to use
    #[clap(
        value_enum,
        short = 'P',
        long,
        value_name = "PROTOCOL",
        env = "ROUGHENOUGH_PROTOCOL",
        default_value_t = ProtocolVersionArg::V14,
    )]
    pub protocol: ProtocolVersionArg,

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
        env = "ROUGHENOUGH_SECRET",
        default_value = ""
    )]
    pub secret: String,

    /// How to store the server's long-term identity while it's running
    #[clap(
        value_enum,
        long,
        value_name = "TYPE",
        env = "ROUGHENOUGH_SECRET_BACKEND",
        default_value_t = SecretBackendArg::Memory
    )]
    pub secret_backend: SecretBackendArg,

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
pub enum ProtocolVersionArg {
    #[value(name = "14")]
    V14,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum SecretBackendArg {
    #[value(name = "memory")]
    Memory,
    #[value(name = "krs")]
    Krs,
    #[value(name = "ssh-agent")]
    SshAgent,
}

impl Display for SecretBackendArg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = self.to_possible_value().unwrap();
        f.write_str(value.get_name())
    }
}

impl Args {
    pub fn udp_socket_addr(&self) -> SocketAddr {
        let addr = self
            .interface
            .parse()
            .expect("invalid IP address or interface name");

        SocketAddr::new(addr, self.port)
    }

    pub fn version(&self) -> Version {
        match self.protocol {
            ProtocolVersionArg::V14 => Version::RfcDraft14,
        }
    }

    /// How long the short-term response signing key is valid
    pub fn rotation_interval(&self) -> Duration {
        Duration::from_secs(self.rotation_interval as u64 * 60 * 60)
    }
}

fn default_num_threads() -> u16 {
    std::thread::available_parallelism().unwrap().get() as u16
}
