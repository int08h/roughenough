#![allow(dead_code)] // compiled both as a bin and a lib module

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use data_encoding::{
    BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, DecodeError, DecodeKind, HEXLOWER, HEXUPPER,
};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::{Nonce, PublicKey};
use roughenough_protocol::{FromFrame, ToFrame};
use tracing::{debug, info, warn};

// Load generator with bounded in-flight requests per worker and per-request
// RTT measurement. Each worker binds its own source socket (so SO_REUSEPORT
// hashing on the server spreads flows across its workers) and keeps up to
// --in-flight requests outstanding. Responses are matched to requests via
// the echoed NONC tag (the request sequence number is embedded in the nonce),
// so reordering under depth > 1 cannot corrupt RTT samples; requests that
// see no response within the expiry window count as losses, never as
// samples. The final report gives percentiles, not averages.

#[derive(Parser, Debug, Clone)]
#[command(version = "2.0.0", about = "Roughenough load generator")]
pub struct Args {
    #[clap(
        required = true,
        requires = "port",
        help = "Target hostname (e.g. roughtime.int08h.com)"
    )]
    pub hostname: String,

    #[clap(
        required = true,
        requires = "hostname",
        help = "Target port (e.g. 2002)"
    )]
    pub port: u16,

    #[clap(
        short = 'n',
        long,
        value_name = "N",
        required = false,
        help = "Number of requests to send per worker",
        default_value_t = 1
    )]
    pub num_requests: usize,

    #[clap(
        short = 'w',
        long,
        value_name = "N",
        required = false,
        help = "Number of load generation tasks to run in parallel",
        default_value_t = 1
    )]
    pub num_workers: usize,

    #[clap(
        short = 'f',
        long,
        value_name = "N",
        required = false,
        help = "Maximum requests in flight per worker",
        default_value_t = 1
    )]
    pub in_flight: usize,

    #[clap(
        short = 'k',
        long,
        value_name = "KEY",
        required = false,
        help = "Server's public key"
    )]
    pub public_key: Option<String>,

    #[clap(
        short = 'v',
        long,
        action = clap::ArgAction::Count,
        help = "Log more details; specify multiple times for more detail"
    )]
    pub verbose: u8,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub num_sent: AtomicUsize,
    pub bytes_sent: AtomicUsize,
    pub num_responses: AtomicUsize,
    pub bytes_received: AtomicUsize,
    pub num_timeouts: AtomicUsize,
    pub num_errors: AtomicUsize,
    pub last_update: AtomicU64,
}

impl Stats {
    pub fn display_loop(stats: Arc<Stats>, done: Arc<AtomicBool>) {
        let delay = Duration::from_secs(2);

        fn now() -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        }

        stats.last_update.store(now(), Relaxed);

        while !done.load(Relaxed) {
            thread::sleep(delay);

            let num_sent = stats.num_sent.load(Relaxed);
            let bytes_sent = stats.bytes_sent.load(Relaxed);
            let num_responses = stats.num_responses.load(Relaxed);
            let bytes_received = stats.bytes_received.load(Relaxed);
            let num_timeouts = stats.num_timeouts.load(Relaxed);
            let num_errors = stats.num_errors.load(Relaxed);
            let last_update = stats.last_update.load(Relaxed);
            stats.reset();

            let now = now();
            stats.last_update.store(now, Relaxed);

            let elapsed_secs = (now - last_update) as f64 / 1000.0;
            let req_ps = num_sent as f64 / elapsed_secs;
            let bsent_ps = bytes_sent as f64 / elapsed_secs;
            let resp_ps = num_responses as f64 / elapsed_secs;
            let brecv_ps = bytes_received as f64 / elapsed_secs;
            let err_ps = num_errors as f64 / elapsed_secs;
            let to_ps = num_timeouts as f64 / elapsed_secs;

            info!(
                "sent: {} reqs, {:.2} reqs/s, {:.2} MiB/s",
                num_sent,
                req_ps,
                bsent_ps / 1024.0 / 1024.0
            );
            info!(
                "recv: {} resps, {:.2} resps/s, {:.2} MiB/s",
                num_responses,
                resp_ps,
                brecv_ps / 1024.0 / 1024.0
            );
            info!(
                "errs: {} errs, {:.2} errs/s  to: {} timeouts, {:.2} to/s",
                num_errors, err_ps, num_timeouts, to_ps
            );
        }
    }

    pub fn reset(&self) {
        self.num_sent.store(0, Relaxed);
        self.bytes_sent.store(0, Relaxed);
        self.num_responses.store(0, Relaxed);
        self.bytes_received.store(0, Relaxed);
        self.num_timeouts.store(0, Relaxed);
        self.num_errors.store(0, Relaxed);
        self.last_update.store(0, Relaxed);
    }
}

/// Per-worker outcome: RTT samples (nanoseconds) for matched responses only
#[derive(Debug, Default)]
pub struct WorkerReport {
    pub rtt_nanos: Vec<u64>,
    pub sent: usize,
    pub received: usize,
    pub lost: usize,
}

fn main() {
    let args = Args::parse();
    enable_logging(&args);
    debug!("command line: {:?}", args);

    let _pub_key = args
        .public_key
        .as_ref()
        .map(|key| try_decode_key(key).unwrap());

    let stats = Arc::new(Stats::default());
    let done = Arc::new(AtomicBool::new(false));

    let display_thread = {
        let stats = Arc::clone(&stats);
        let done = Arc::clone(&done);
        thread::spawn(move || Stats::display_loop(stats, done))
    };

    let start = Instant::now();
    let mut workers = Vec::new();
    for idx in 0..args.num_workers {
        let args = args.clone();
        let stats = Arc::clone(&stats);
        workers.push(thread::spawn(move || run_worker(idx, args, stats)));
    }

    let reports: Vec<WorkerReport> = workers
        .into_iter()
        .map(|w| w.join().expect("worker panicked"))
        .collect();
    let wall = start.elapsed();

    done.store(true, Relaxed);
    display_thread.join().expect("display thread panicked");

    print_report(&reports, wall);
}

fn print_report(reports: &[WorkerReport], wall: Duration) {
    let sent: usize = reports.iter().map(|r| r.sent).sum();
    let received: usize = reports.iter().map(|r| r.received).sum();
    let lost: usize = reports.iter().map(|r| r.lost).sum();

    let mut rtts: Vec<u64> = reports
        .iter()
        .flat_map(|r| r.rtt_nanos.iter().copied())
        .collect();
    rtts.sort_unstable();

    let loss_pct = if sent > 0 {
        100.0 * lost as f64 / sent as f64
    } else {
        0.0
    };
    let rps = received as f64 / wall.as_secs_f64();

    info!("---- final report ----");
    info!(
        "sent {} requests, received {} responses, lost {} ({:.3}%)",
        sent, received, lost, loss_pct
    );
    info!(
        "wall time {:.3}s, {:.0} responses/s",
        wall.as_secs_f64(),
        rps
    );

    if rtts.is_empty() {
        info!("rtt: no samples");
        return;
    }
    let us = |nanos: u64| nanos as f64 / 1000.0;
    info!(
        "rtt: min {:.1}us p50 {:.1}us p90 {:.1}us p99 {:.1}us max {:.1}us ({} samples)",
        us(rtts[0]),
        us(percentile(&rtts, 0.50)),
        us(percentile(&rtts, 0.90)),
        us(percentile(&rtts, 0.99)),
        us(*rtts.last().unwrap()),
        rtts.len()
    );
}

/// Nearest-rank percentile over a sorted, non-empty slice
fn percentile(sorted: &[u64], p: f64) -> u64 {
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// How long an unanswered request stays in the window before it is declared
/// lost. Kept well above any healthy RTT so losses, not slow responses, are
/// what expire; expired responses that arrive later are ignored.
const EXPIRY: Duration = Duration::from_millis(150);

fn run_worker(idx: usize, args: Args, stats: Arc<Stats>) -> WorkerReport {
    // one source socket per worker so the server's SO_REUSEPORT hashing
    // spreads the workers across its threads
    let source = UdpSocket::bind("0.0.0.0:0").unwrap();
    // short recv timeout: it paces the loss-expiry sweep, not the RTT budget
    source
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();

    info!("worker {idx} starting, {source:?}");

    let target_addr: SocketAddr = format!("{}:{}", args.hostname, args.port)
        .to_socket_addrs()
        .expect("cannot resolve target")
        .next()
        .expect("target resolved to no addresses");

    // random filler keeps nonces distinct across workers and runs; the
    // sequence number is patched into the first 8 bytes of each nonce and
    // echoed back in the response's NONC tag for RTT correlation
    let nonce_filler = random_bytes::<32>();
    let in_flight_cap = args.in_flight.max(1);
    let total = args.num_requests as u64;

    let mut outstanding: HashMap<u64, Instant> = HashMap::with_capacity(in_flight_cap);
    let mut report = WorkerReport {
        rtt_nanos: Vec::with_capacity(args.num_requests),
        ..WorkerReport::default()
    };
    let mut next_seq: u64 = 0;
    let mut completed: u64 = 0;
    let mut buf = [0u8; 1024];

    while completed < total {
        while outstanding.len() < in_flight_cap && next_seq < total {
            let mut nonce_bytes = nonce_filler;
            nonce_bytes[..8].copy_from_slice(&next_seq.to_le_bytes());
            let request = Request::new(&Nonce::from(nonce_bytes));
            let request_bytes = request.as_frame_bytes().unwrap();

            match source.send_to(&request_bytes, target_addr) {
                Ok(n) => {
                    stats.num_sent.fetch_add(1, Relaxed);
                    stats.bytes_sent.fetch_add(n, Relaxed);
                    outstanding.insert(next_seq, Instant::now());
                    report.sent += 1;
                    next_seq += 1;
                }
                Err(e) => {
                    stats.num_errors.fetch_add(1, Relaxed);
                    warn!("worker {idx} send error: {e:?}");
                    // count as lost so the run cannot deadlock on send errors
                    report.lost += 1;
                    completed += 1;
                    next_seq += 1;
                }
            }
        }

        match source.recv_from(&mut buf) {
            Ok((n, _)) => {
                stats.num_responses.fetch_add(1, Relaxed);
                stats.bytes_received.fetch_add(n, Relaxed);

                if let Some(seq) = response_seq(&mut buf[..n])
                    && let Some(sent_at) = outstanding.remove(&seq)
                {
                    report.rtt_nanos.push(sent_at.elapsed().as_nanos() as u64);
                    report.received += 1;
                    completed += 1;
                }
                // unmatched: unparseable, duplicate, or already expired --
                // it was (or will be) accounted through the expiry sweep
            }
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                stats.num_timeouts.fetch_add(1, Relaxed);
                // expire the window so losses never wedge it; timeouts are
                // losses, never RTT samples
                let now = Instant::now();
                let before = outstanding.len();
                outstanding.retain(|_, sent_at| now.duration_since(*sent_at) < EXPIRY);
                let expired = before - outstanding.len();
                report.lost += expired;
                completed += expired as u64;
            }
            Err(e) => {
                stats.num_errors.fetch_add(1, Relaxed);
                warn!("worker {idx} recv error: {e:?}");
            }
        }
    }

    report
}

/// Extract the sequence number echoed in the response's NONC tag
fn response_seq(bytes: &mut [u8]) -> Option<u64> {
    let mut cursor = ParseCursor::new(bytes);
    let response = Response::from_frame(&mut cursor).ok()?;
    let nonce_bytes: &[u8] = response.nonc().as_ref();
    Some(u64::from_le_bytes(nonce_bytes[..8].try_into().ok()?))
}

fn enable_logging(args: &Args) {
    let mut builder = tracing_subscriber::fmt().compact();

    match args.verbose {
        2.. => builder = builder.with_max_level(tracing::Level::TRACE),
        1 => builder = builder.with_max_level(tracing::Level::DEBUG),
        _ => builder = builder.with_max_level(tracing::Level::INFO),
    }

    builder.init();
}

pub fn try_decode_key(encoded_key: &str) -> Result<PublicKey, DecodeError> {
    let key = try_decode(encoded_key)?;

    if key.len() != 32 {
        return Err(DecodeError {
            position: key.len(),
            kind: DecodeKind::Length,
        });
    }

    Ok(PublicKey::from(key.as_slice()))
}

/// Attempt to decode `encoded_value` into a `Vec<u8>` using multiple encoding formats until
/// one succeeds.
pub fn try_decode(encoded_value: &str) -> Result<Vec<u8>, DecodeError> {
    // Try all supported encodings
    let value = HEXLOWER
        .decode(encoded_value.as_bytes())
        .or_else(|_| HEXUPPER.decode(encoded_value.as_bytes()))
        .or_else(|_| BASE64.decode(encoded_value.as_bytes()))
        .or_else(|_| BASE64_NOPAD.decode(encoded_value.as_bytes()))
        .or_else(|_| BASE64URL.decode(encoded_value.as_bytes()))
        .or_else(|_| BASE64URL_NOPAD.decode(encoded_value.as_bytes()))?;

    Ok(value)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut val = [0u8; N];
    aws_lc_rs::rand::fill(&mut val).expect("should be infallible");
    val
}
