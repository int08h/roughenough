#![doc(hidden)]

use clap::builder::RangedU64ValueParser;
use clap::{Parser, ValueEnum};
use roughenough_protocol::tags::ProtocolVersion;

/// Arguments for the client CLI
#[derive(Parser, Debug)]
#[command(version, about = "Roughenough roughtime client")]
pub struct Args {
    #[clap(
        required = false,
        requires = "port",
        help = "Server hostname (e.g. roughtime.int08h.com)"
    )]
    pub hostname: Option<String>,

    #[clap(
        required = false,
        requires = "hostname",
        help = "Server port (e.g. 2003)"
    )]
    pub port: Option<u16>,

    #[clap(long, help = "Display the time as seconds since the epoch (UTC)")]
    pub epoch: bool,

    #[clap(
        short = 'f',
        long,
        value_name = "FORMAT",
        help = "The strftime() format string to display the date and time",
        default_value = "%Y-%m-%d %H:%M:%S %Z"
    )]
    pub time_format: String,

    #[clap(
        short = 'k',
        long,
        value_name = "KEY",
        help = "Public key of server (base64 or hex)"
    )]
    pub pub_key: Option<String>,

    #[clap(
        short = 'n',
        long,
        value_name = "N",
        help = "Number of requests to send",
        default_value_t = 1,
        value_parser = RangedU64ValueParser::<usize>::new().range(1..)
    )]
    pub num_requests: usize,

    /// Roughtime protocol version(s) to offer the server
    #[clap(
        short = 'P',
        long = "protocol",
        value_enum,
        value_name = "VERSION",
        default_value_t = VersionArg::V19,
    )]
    pub protocol: VersionArg,

    #[clap(
        short = 'l',
        long,
        value_name = "FILE",
        help = "File containing servers to query, JSON format"
    )]
    pub server_list: Option<String>,

    #[clap(
        short = 'u',
        long,
        value_name = "N",
        help = "Number of different servers to query",
        requires = "server_list",
        default_value_t = 3,
        value_parser = RangedU64ValueParser::<usize>::new().range(1..)
    )]
    pub num_unique_servers: usize,

    #[clap(
        short = 'r',
        long,
        value_name = "N",
        help = "Number of times to repeat the chained measurement sequence",
        requires = "server_list",
        default_value_t = 2,
        value_parser = RangedU64ValueParser::<usize>::new().range(1..)
    )]
    pub num_measurement_rounds: usize,

    #[clap(
        short = 'q',
        long,
        conflicts_with = "verbose",
        help = "Don't print any messages except for errors",
        default_value_t = false
    )]
    pub quiet: bool,

    #[clap(
        long = "report",
        help = "Send malfeasance reports when causality violations are detected",
        default_value_t = false
    )]
    pub send_report: bool,

    #[clap(
        short = 's',
        long = "set-clock",
        requires = "pub_key",
        help = "Set the system's clock to the received time (requires -k)",
        default_value_t = false
    )]
    pub set_clock: bool,

    #[clap(
        short = 't',
        long,
        value_name = "TIMEOUT",
        help = "Seconds to wait for the server's response",
        default_value_t = 2
    )]
    pub timeout: u16,

    #[clap(
        short = 'v',
        long,
        conflicts_with = "quiet",
        action = clap::ArgAction::Count,
        help = "Output details about requests and responses; specify multiple times for more detail"
    )]
    pub verbose: u8,

    #[clap(
        long,
        help = "Display time in UTC [default: local time]",
        default_value_t = false
    )]
    pub zulu: bool,
}

/// Roughtime protocol version(s) the client offers in its requests.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionArg {
    /// Offer only draft version 0x8000000c (the default)
    #[value(name = "19")]
    V19,
    /// Offer only RFC version 1
    #[value(name = "1")]
    V1,
    /// Offer RFC version 1 and the draft version
    #[value(name = "both")]
    Both,
}

impl VersionArg {
    /// The version list to offer, or `None` to use the client default
    pub fn offered(&self) -> Option<Vec<ProtocolVersion>> {
        match self {
            VersionArg::V19 => None,
            VersionArg::V1 => Some(vec![ProtocolVersion::RFC]),
            VersionArg::Both => Some(vec![ProtocolVersion::RFC, ProtocolVersion::DRAFT]),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use clap::error::ErrorKind;

    use super::Args;

    #[test]
    fn set_clock_without_pub_key_is_rejected() {
        let err = Args::try_parse_from(["prog", "host", "2003", "-s"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--pub-key"));
    }

    #[test]
    fn set_clock_with_pub_key_parses() {
        let args = Args::try_parse_from(["prog", "host", "2003", "-s", "-k", "abc123"]).unwrap();
        assert!(args.set_clock);
        assert_eq!(args.pub_key.as_deref(), Some("abc123"));
    }

    #[test]
    fn zero_num_requests_is_rejected() {
        let err = Args::try_parse_from(["prog", "host", "2003", "-n", "0"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn zero_num_unique_servers_is_rejected() {
        let err = Args::try_parse_from(["prog", "-l", "servers.json", "-u", "0"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn zero_num_measurement_rounds_is_rejected() {
        let err = Args::try_parse_from(["prog", "-l", "servers.json", "-r", "0"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn version_output_matches_crate_version() {
        let err = Args::try_parse_from(["prog", "--version"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn nonzero_counts_parse() {
        let args = Args::try_parse_from(["prog", "host", "2003", "-n", "1"]).unwrap();
        assert_eq!(args.num_requests, 1);

        let args =
            Args::try_parse_from(["prog", "-l", "servers.json", "-u", "2", "-r", "3"]).unwrap();
        assert_eq!(args.num_unique_servers, 2);
        assert_eq!(args.num_measurement_rounds, 3);
    }
}
