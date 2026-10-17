//! The main client CLI

mod args;

use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use jiff::Timestamp;
use jiff::tz::TimeZone;
use roughenough_client::client::try_decode_key;
use roughenough_client::measurement::Measurement;
#[cfg(feature = "reporting")]
use roughenough_client::reporting::MalfeasanceReport;
use roughenough_client::sequence::MeasurementSequence;
use roughenough_client::server_list::ServerList;
use roughenough_client::{CausalityViolation, Client, ClientError};
use tracing::{Level, debug, error, info};

use crate::args::Args;

fn main() {
    let args = Args::parse();

    enable_logging(&args);
    debug!("command line: {:?}", args);

    let midpoint = if let Some(list_file) = &args.server_list {
        query_multiple_servers(&args, list_file)
    } else {
        let hostname = args
            .hostname
            .as_deref()
            .expect("clap requires a hostname without --server-list");
        Some(query_single_server(&args, hostname))
    };

    if args.set_clock {
        match clock_target(midpoint) {
            Ok(midpoint) => set_system_clock(midpoint),
            Err(msg) => {
                error!("{msg}");
                std::process::exit(1);
            }
        }
    }
}

/// The time to set the clock to. A sequence with causality violations is refused: the servers
/// disagree about the time, and the client cannot tell which of them is wrong.
fn clock_target(midpoint: Option<u64>) -> Result<u64, &'static str> {
    midpoint.ok_or("Causality violations detected; not setting the system clock")
}

fn query_single_server(args: &Args, hostname: &str) -> u64 {
    let port = args.port.unwrap();

    if args.pub_key.is_none() {
        // bypasses the logger on purpose to be loud
        eprintln!("WARNING: no public key provided (-k); responses are NOT authenticated");
    }

    let client = build_client(args, hostname, port, hostname, args.pub_key.as_deref())
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

/// Returns the midpoint of the last measurement, or `None` if causality violations were found.
fn query_multiple_servers(args: &Args, list_file: &str) -> Option<u64> {
    let server_list = ServerList::from_file(list_file).unwrap_or_else(|e| {
        error!("Loading server list from '{list_file}': {e}");
        std::process::exit(-1);
    });

    #[cfg(feature = "reporting")]
    if args.send_report && server_list.reporting_url().is_none() {
        error!("--report requires a 'reports' URL in the server list");
        std::process::exit(-1);
    }

    let clients = clients_from_list(&server_list, args).unwrap_or_else(|e| {
        error!("Processing '{list_file}': {e}");
        std::process::exit(-1);
    });

    let sequence = MeasurementSequence::new(clients);
    let measurements = sequence
        .run(args.num_measurement_rounds)
        .unwrap_or_else(|e| {
            error!("Could not complete measurement sequence: {e}");
            std::process::exit(-1);
        });

    let violations = CausalityViolation::find(&measurements);

    if violations.is_empty() {
        return Some(measurements.last().unwrap().midpoint());
    }

    for violation in &violations {
        display_violation(args, violation);
    }

    #[cfg(feature = "reporting")]
    if args.send_report
        && let Some(url) = server_list.reporting_url()
    {
        for violation in &violations {
            let report = MalfeasanceReport::from_violation(violation);
            match report.submit(url) {
                Ok(()) => info!("Sent malfeasance report to {url}"),
                Err(e) => error!("Failed to send malfeasance report to {url}: {e}"),
            }
        }
    }

    None
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
    let level = match (args.quiet, args.verbose) {
        (true, _) => Level::ERROR,
        (false, 2..) => Level::TRACE,
        (false, 1) => Level::DEBUG,
        (false, 0) => Level::INFO,
    };

    tracing_subscriber::fmt()
        .compact()
        .with_max_level(level)
        .init();
}

fn build_client(
    args: &Args,
    host: &str,
    port: u16,
    display_name: &str,
    encoded_key: Option<&str>,
) -> Result<Client, ClientError> {
    // Users write IPv6 literals bracketed ("[::1]"), as in URLs and host:port strings, but
    // resolving a (host, port) pair needs the bare address
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| ClientError::DnsLookupFailed(format!("{host}:{port}")))?;
    let mut builder = Client::builder(addr)
        .hostname(display_name)
        .timeout(Duration::from_secs(u64::from(args.timeout)));
    if let Some(key) = encoded_key {
        let public_key = try_decode_key(key)?;
        builder = builder.public_key(public_key);
    }
    if let Some(versions) = args.protocol.offered() {
        builder = builder.versions(versions);
    }
    builder.build()
}

fn clients_from_list(
    server_list: &ServerList,
    args: &Args,
) -> Result<Vec<Client>, Box<dyn std::error::Error>> {
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

    let mut clients = Vec::new();

    for server in &target_servers {
        let Some(address) = server.first_udp_address() else {
            info!("Server '{}' has no UDP address, skipping it", server.name());
            continue;
        };

        let client = build_client(
            args,
            address.host(),
            address.port(),
            server.name(),
            Some(server.public_key()),
        )?;
        clients.push(client);
    }

    if clients.is_empty() {
        return Err("no server in the list has a UDP address".into());
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
    let m1_lower = format_time(violation.lower_bound_i(), args);
    let m2_upper = format_time(violation.upper_bound_j(), args);

    error!("=== Causality violation ===");
    error!("");
    error!("Measurement A (requested first from {}):", m1.hostname());
    error!("  Server:   {}", m1.server());
    error!(
        "  Time:     {} +/- {}s",
        format_time(m1.midpoint(), args),
        m1.radius()
    );
    error!("  Earliest: {m1_lower}");
    error!("");
    error!("Measurement B (requested second from {}):", m2.hostname());
    error!("  Server:   {}", m2.server());
    error!(
        "  Time:     {} +/- {}s",
        format_time(m2.midpoint(), args),
        m2.radius()
    );
    error!("  Latest:   {m2_upper}");
    error!("");
    error!("Problem: A earliest ({m1_lower}) > B latest ({m2_upper})");

    if m1.server() == m2.server() {
        error!(
            "Note: Both measurements are from the SAME server - suggesting an issue with the server and/or its clock"
        );
    }
    error!("===========================");
}

/// Format an epoch-seconds value from a (possibly hostile) server.
fn format_time(seconds: u64, args: &Args) -> String {
    if args.epoch {
        return seconds.to_string();
    }

    let Some(ts) = i64::try_from(seconds)
        .ok()
        .and_then(|s| Timestamp::from_second(s).ok())
    else {
        return format!("<unrepresentable time: {seconds} sec>");
    };

    // A bare Timestamp has no time zone, so %Z would print literally; format a UTC Zoned instead
    let tz = if args.zulu {
        TimeZone::UTC
    } else {
        TimeZone::system()
    };
    ts.to_zoned(tz).strftime(&args.time_format).to_string()
}

fn display_measurement(args: &Args, measurement: &Measurement) {
    let time = format_time(measurement.midpoint(), args);
    if args.epoch {
        info!("{time}");
    } else {
        info!("{time} (+/-{}s)", measurement.radius());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_server_client_uses_timeout_flag() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = silent.local_addr().unwrap().port().to_string();
        let args = Args::try_parse_from(["prog", "127.0.0.1", &port, "-t", "1"]).unwrap();

        let hostname = args.hostname.as_deref().unwrap();
        let client = build_client(
            &args,
            hostname,
            args.port.unwrap(),
            hostname,
            args.pub_key.as_deref(),
        )
        .unwrap();

        let start = std::time::Instant::now();
        let result = client.query();
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ClientError::ServerTimeout)),
            "expected ServerTimeout, got {result:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed < Duration::from_millis(1900),
            "single-server wait was {elapsed:?}, expected about 1s"
        );
    }

    #[test]
    fn ipv6_host_resolves_with_or_without_brackets() {
        let args = Args::try_parse_from(["prog", "::1", "2002"]).unwrap();
        let expected: std::net::SocketAddr = "[::1]:2002".parse().unwrap();

        for host in ["::1", "[::1]"] {
            let client = build_client(&args, host, 2002, host, None)
                .unwrap_or_else(|e| panic!("{host}: {e}"));
            assert_eq!(client.server(), expected, "{host}");
        }
    }

    fn parse(extra: &[&str]) -> Args {
        let mut argv = vec!["prog", "host", "2003"];
        argv.extend_from_slice(extra);
        Args::try_parse_from(argv).unwrap()
    }

    #[test]
    fn format_time_zulu_uses_utc_and_format() {
        let args = parse(&["--zulu", "-f", "%Y-%m-%d %H:%M:%S %Z"]);
        assert_eq!(format_time(1_748_359_193, &args), "2025-05-27 15:19:53 UTC");
    }

    #[test]
    fn format_time_epoch_prints_raw_seconds() {
        let args = parse(&["--epoch"]);
        assert_eq!(format_time(1_748_359_193, &args), "1748359193");
        // Raw seconds need no conversion, so even values jiff cannot represent print as is
        assert_eq!(format_time(u64::MAX, &args), u64::MAX.to_string());
    }

    #[test]
    fn format_time_falls_back_on_unrepresentable_value() {
        let args = parse(&["--zulu"]);
        assert_eq!(
            format_time(300_000_000_000, &args),
            "<unrepresentable time: 300000000000 sec>"
        );
    }

    #[test]
    fn format_time_does_not_wrap_u64_max() {
        // u64 values beyond i64::MAX must not wrap into the valid range
        let args = parse(&["--zulu"]);
        assert_eq!(
            format_time(u64::MAX, &args),
            format!("<unrepresentable time: {} sec>", u64::MAX)
        );
    }

    #[test]
    fn clock_is_not_set_when_violations_found() {
        assert!(clock_target(None).is_err());
        assert_eq!(clock_target(Some(1_748_359_193)), Ok(1_748_359_193));
    }
}
