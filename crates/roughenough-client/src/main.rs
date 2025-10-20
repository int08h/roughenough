//! The main client CLI

use std::net::ToSocketAddrs;
use std::time::Duration;

use chrono::{DateTime, Local};
use clap::Parser;
use roughenough_client::ClientError::DnsLookupFailed;
use roughenough_client::args::Args;
use roughenough_client::measurement::Measurement;
use roughenough_client::reporting::MalfeasanceReport;
use roughenough_client::sequence::MeasurementSequence;
use roughenough_client::server_list::ServerList;
use roughenough_client::{CausalityViolation, Client, ResponseValidator, server_list};
use roughenough_common::encoding::try_decode_key;
use tracing::{debug, error, info};

#[derive(thiserror::Error, Debug)]
enum CliError {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Client(#[from] roughenough_client::ClientError),

    #[error("{0}")]
    ServerList(#[from] server_list::Error),

    #[error("{0}")]
    Decode(#[from] data_encoding::DecodeError),
}

fn main() {
    let args = Args::parse();

    enable_logging(&args);
    debug!("command line: {:?}", args);

    let midpoint = match (&args.hostname, &args.server_list) {
        // Simple case, query a single server
        (Some(hostname), None) => query_single_server(&args, hostname),
        // Measurement sequence of multiple servers
        (None, Some(list_file)) => query_multiple_servers(&args, list_file),
        _ => {
            error!(
                "Specify 'hostname' and 'port', or use '--server-list' to query multiple servers (see --help for details)"
            );
            std::process::exit(-1);
        }
    };

    if args.set_clock {
        set_system_clock(midpoint);
    };
}

fn query_single_server(args: &Args, hostname: &String) -> u64 {
    let port = args.port.unwrap();

    let client = Client::new(hostname, port, args.pub_key.as_deref()).unwrap_or_else(|e| {
        error!("Error creating client for '{hostname}:{port}': {e}");
        std::process::exit(-1);
    });

    let mut midpoint: u64 = 0;
    for _ in 0..args.num_requests {
        let measurement = client.query().unwrap_or_else(|e| {
            error!("Error querying '{hostname}:{port}': {e}");
            std::process::exit(-1);
        });

        display_measurement(args, &measurement);
        midpoint = measurement.midpoint();
    }

    // Return the last midpoint received
    midpoint
}

fn query_multiple_servers(args: &Args, list_file: &String) -> u64 {
    let server_list = ServerList::from_file(list_file).unwrap_or_else(|e| {
        error!("Loading server list from '{list_file}': {e}");
        std::process::exit(-1);
    });

    let clients = clients_from_list(&server_list, args).unwrap_or_else(|e| {
        error!("Processing '{list_file}': {e}");
        std::process::exit(-1);
    });

    let mut sequence = MeasurementSequence::new(clients);
    let measurements = sequence
        .run(args.num_measurement_rounds)
        .unwrap_or_else(|e| {
            error!("Could not complete measurement sequence: {e}");
            std::process::exit(-1);
        });

    let violations = ResponseValidator::validate_causality(&measurements);

    if !violations.is_empty() {
        for violation in &violations {
            display_violation(args, violation);
        }

        if args.send_report
            && let Some(report_url) = server_list.reporting_url()
        {
            info!("Sending malfeasance report to: {}", report_url);

            for violation in &violations {
                let report = MalfeasanceReport::from_violation(violation);
                if let Err(e) = report.submit(report_url) {
                    error!("Failed to send malfeasance report: {e}");
                }
            }
        }
    }

    // Return midpoint from the last measurement
    measurements.last().unwrap().midpoint()
}

fn set_system_clock(midpoint: u64) {
    assert!(
        midpoint > 1_500_000_000,
        "not setting clock to suspicious midpoint: {midpoint}"
    );

    let spec = libc::timespec {
        tv_sec: midpoint as libc::time_t,
        tv_nsec: 0,
    };

    let spec_ptr = &spec as *const libc::timespec;
    let ret = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, spec_ptr) };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        error!("Failed to set system clock: {}", err);
    }
}

fn enable_logging(args: &Args) {
    let mut builder = tracing_subscriber::fmt().compact();

    if args.quiet {
        builder = builder.with_max_level(tracing::Level::ERROR);
    } else {
        match args.verbose {
            2.. => builder = builder.with_max_level(tracing::Level::TRACE),
            1 => builder = builder.with_max_level(tracing::Level::DEBUG),
            _ => builder = builder.with_max_level(tracing::Level::INFO),
        }
    }

    builder.init();
}

fn clients_from_list(server_list: &ServerList, args: &Args) -> Result<Vec<Client>, CliError> {
    let target_servers = server_list.choose_random(args.num_unique_servers)?;

    let chosen_ones = target_servers
        .iter()
        .map(|s| s.name())
        .collect::<Vec<_>>()
        .join(", ");

    debug!(
        "Loaded {} servers; chosen: {}",
        server_list.servers().len(),
        chosen_ones
    );

    let timeout = Duration::from_secs(args.timeout as u64);
    let mut clients = Vec::new();

    for server in target_servers {
        // resolve the address
        let host = server.first_address().host();
        let port = server.first_address().port();
        let addr_str = format!("{host}:{port}");
        let sock_addr = addr_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| DnsLookupFailed(host.to_string()))?;

        let encoded_key = server.public_key();
        let public_key = try_decode_key(encoded_key)?;

        // Build client with all settings
        let client = Client::builder(sock_addr)
            .hostname(server.name())
            .timeout(timeout)
            .public_key(public_key)
            .build();

        clients.push(client);
    }

    Ok(clients)
}

// You might read this and think "can any other types of violation occur?"
//
// The Roughtime protocol defines exactly one causality constraint:
//   * For measurements i and j, where i was received before j:
//     MIDP[i] - RADI[i] <= MIDP[j] + RADI[j]
//
// This translates to: the earliest possible time of measurement i must be less than or equal to the
// latest possible time of measurement j.
//
// There are no other causality violations in Roughtime because:
//   1. Overlapping intervals are allowed - As long as the causality constraint is satisfied, time
//      intervals can overlap
//   2. Midpoints don't need to be monotonic - M1's midpoint can be after M2's midpoint, as long as
//      their intervals satisfy causality
//   3. No other temporal constraints - The protocol doesn't impose any other time-ordering
//      requirements
//
fn display_violation(args: &Args, violation: &CausalityViolation) {
    let m1 = &violation.measurement_i;
    let m2 = &violation.measurement_j;

    let m1_lower = m1.midpoint() - m1.radius() as u64;
    let m2_upper = m2.midpoint() + m2.radius() as u64;

    let m1_lower_dt = DateTime::from_timestamp(m1_lower as i64, 0).unwrap();
    let m1_midpoint_dt = DateTime::from_timestamp(m1.midpoint() as i64, 0).unwrap();
    let m2_upper_dt = DateTime::from_timestamp(m2_upper as i64, 0).unwrap();
    let m2_midpoint_dt = DateTime::from_timestamp(m2.midpoint() as i64, 0).unwrap();

    error!("=== Causality violation ===");
    error!("");
    error!("Measurement A (requested first from {}):", m1.hostname());
    error!("  Server:   {}", m1.server());
    error!(
        "  Time:     {} +/- {}s",
        m1_midpoint_dt.format(&args.time_format),
        m1.radius()
    );
    error!("  Earliest: {}", m1_lower_dt.format(&args.time_format));
    error!("");
    error!("Measurement B (requested second from {}):", m2.hostname());
    error!("  Server:   {}", m2.server());
    error!(
        "  Time:     {} +/- {}s",
        m2_midpoint_dt.format(&args.time_format),
        m2.radius()
    );
    error!("  Latest:   {}", m2_upper_dt.format(&args.time_format));
    error!("");
    error!(
        "Problem: A earliest ({}) > B latest ({})",
        m1_lower_dt.format("%H:%M:%S"),
        m2_upper_dt.format("%H:%M:%S")
    );

    if m1.server() == m2.server() {
        error!(
            "Note: Both measurements are from the SAME server - suggesting an issue with the server and/or its clock"
        );
    }
    error!("===========================");
}

fn display_measurement(args: &Args, measurement: &Measurement) {
    let midpoint = measurement.midpoint();
    let radius = measurement.radius();
    let timestamp = DateTime::from_timestamp(midpoint as i64, 0).unwrap();

    let output = match (args.zulu, args.epoch) {
        (true, false) => format!("{} (+/-{}s)", timestamp.format(&args.time_format), radius),
        (false, false) => format!(
            "{} (+/-{}s)",
            timestamp.with_timezone(&Local).format(&args.time_format),
            radius
        ),
        (_, true) => format!("{}", timestamp.timestamp()),
    };

    info!("{}", output);
}
