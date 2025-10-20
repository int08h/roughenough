#![doc(hidden)]

use clap::Parser;

/// Arguments for the client CLI
#[derive(Parser, Debug)]
#[command(version = "2.0.0", about = "Roughenough roughtime client")]
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
        help = "Server port (e.g. 2002)"
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
        default_value_t = 1
    )]
    pub num_requests: usize,

    #[clap(
        short = 'P',
        long,
        value_name = "PROTOCOL",
        help = "Roughtime version to send; 0 = Google, 14 = RFC draft 14",
        default_value_t = 14
    )]
    pub protocol: usize,

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
        default_value_t = 3
    )]
    pub num_unique_servers: usize,

    #[clap(
        short = 'r',
        long,
        value_name = "N",
        help = "Number of times to repeat the chained measurement sequence",
        requires = "server_list",
        default_value_t = 2
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
        help = "Set the system's clock to the received time",
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
