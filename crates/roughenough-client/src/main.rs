//! The main client CLI

use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use jiff::Timestamp;
use jiff::tz::TimeZone;
use roughenough_client::ClientError::{DnsLookupFailed, InvalidConfiguration};
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

    if args.pub_key.is_none() {
        // bypasses the logger on purpose to be loud
        eprintln!("WARNING: no public key provided (-k); responses are NOT authenticated");
    }

    let versions = args.protocol.offered();
    let client =
        Client::new_with_versions(hostname, port, args.pub_key.as_deref(), versions.as_deref())
            .unwrap_or_else(|e| {
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

    for server in &target_servers {
        let Some(address) = server.first_udp_address() else {
            info!("Server '{}' has no UDP address, skipping it", server.name());
            continue;
        };

        let host = address.host();
        let port = address.port();
        let sock_addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| DnsLookupFailed(host.to_string()))?;

        let encoded_key = server.public_key();
        let public_key = try_decode_key(encoded_key)?;

        let mut builder = Client::builder(sock_addr)
            .hostname(server.name())
            .timeout(timeout)
            .public_key(public_key);

        if let Some(versions) = args.protocol.offered() {
            builder = builder.versions(&versions);
        }

        clients.push(builder.build());
    }

    if clients.is_empty() {
        return Err(CliError::Client(InvalidConfiguration(
            "no server has a UDP address".to_string(),
        )));
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
    let m1 = violation.measurement_i();
    let m2 = violation.measurement_j();

    let m1_lower = m1.lower_bound();
    let m2_upper = m2.upper_bound();

    error!("=== Causality violation ===");
    error!("");
    error!("Measurement A (requested first from {}):", m1.hostname());
    error!("  Server:   {}", m1.server());
    error!(
        "  Time:     {} +/- {}s",
        format_seconds(m1.midpoint(), &args.time_format),
        m1.radius()
    );
    error!(
        "  Earliest: {}",
        format_seconds(m1_lower, &args.time_format)
    );
    error!("");
    error!("Measurement B (requested second from {}):", m2.hostname());
    error!("  Server:   {}", m2.server());
    error!(
        "  Time:     {} +/- {}s",
        format_seconds(m2.midpoint(), &args.time_format),
        m2.radius()
    );
    error!(
        "  Latest:   {}",
        format_seconds(m2_upper, &args.time_format)
    );
    error!("");
    error!(
        "Problem: A earliest ({}) > B latest ({})",
        format_seconds(m1_lower, "%H:%M:%S"),
        format_seconds(m2_upper, "%H:%M:%S")
    );

    if m1.server() == m2.server() {
        error!(
            "Note: Both measurements are from the SAME server - suggesting an issue with the server and/or its clock"
        );
    }
    error!("===========================");
}

/// Format an epoch-seconds value from a (possibly hostile) server.
fn format_seconds(seconds: u64, time_format: &str) -> String {
    let timestamp = i64::try_from(seconds)
        .ok()
        .and_then(|s| Timestamp::from_second(s).ok());

    match timestamp {
        Some(ts) => ts.strftime(time_format).to_string(),
        None => format!("<unrepresentable time: {seconds} sec>"),
    }
}

fn format_measurement(measurement: &Measurement, zulu: bool, epoch: bool, fmt: &str) -> String {
    let midpoint = measurement.midpoint();
    let radius = measurement.radius();

    let Some(timestamp) = measurement.midpoint_datetime() else {
        return format!("<unrepresentable midpoint: {midpoint} sec> (+/-{radius}s)");
    };

    match (zulu, epoch) {
        (true, false) => format!("{} (+/-{}s)", timestamp.strftime(fmt), radius),
        (false, false) => {
            let local_time = timestamp.to_zoned(TimeZone::system());
            format!("{} (+/-{}s)", local_time.strftime(fmt), radius)
        }
        (_, true) => format!("{}", timestamp.as_second()),
    }
}

fn display_measurement(args: &Args, measurement: &Measurement) {
    let output = format_measurement(measurement, args.zulu, args.epoch, &args.time_format);
    info!("{}", output);
}

#[cfg(test)]
mod tests {
    use roughenough_protocol::ToFrame;
    use roughenough_protocol::tags::PublicKey;
    use roughenough_server::test_utils::TestContext;

    use super::*;

    fn create_measurement(midpoint: u64) -> Measurement {
        let mut ctx = TestContext::new(64);
        let (req, resp) = ctx.create_interaction_pair(midpoint);
        let resp_bytes = resp.as_frame_bytes().unwrap();
        let pubkey = PublicKey::from(ctx.key_source.public_key_bytes());

        Measurement::builder()
            .server("127.0.0.1:8000".parse().unwrap())
            .request(req)
            .response(resp)
            .response_bytes(resp_bytes)
            .hostname("test".to_string())
            .public_key(Some(pubkey))
            .rand_value(None)
            .build()
            .unwrap()
    }

    #[test]
    fn unrepresentable_midpoint_falls_back_to_raw_value() {
        let measurement = create_measurement(300_000_000_000);
        let output = format_measurement(&measurement, true, false, "%Y-%m-%d %H:%M:%S %Z");
        assert!(
            output.contains("<unrepresentable midpoint: 300000000000 sec>"),
            "unexpected output: {output}"
        );
    }

    #[test]
    fn sane_midpoint_formats_normally() {
        let measurement = create_measurement(1_748_359_193);
        let output = format_measurement(&measurement, true, false, "%Y-%m-%d");
        assert!(
            output.starts_with("2025-05-27"),
            "unexpected output: {output}"
        );
    }

    #[test]
    fn format_seconds_falls_back_on_unrepresentable_values() {
        assert_eq!(
            format_seconds(300_000_000_000, "%H:%M:%S"),
            "<unrepresentable time: 300000000000 sec>"
        );
        // u64 values beyond i64::MAX must not wrap into the valid range
        assert_eq!(
            format_seconds(u64::MAX, "%H:%M:%S"),
            format!("<unrepresentable time: {} sec>", u64::MAX)
        );
        assert_eq!(format_seconds(0, "%Y-%m-%d"), "1970-01-01");
    }
}
