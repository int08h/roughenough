#![allow(dead_code)] // there are a lot of false positives that I'll deal with later

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use data_encoding::{
    BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, DecodeError, DecodeKind, HEXLOWER, HEXUPPER,
};
use protocol::ToFrame;
use protocol::request::Request;
use protocol::tags::{Nonce, PublicKey};
use tracing::{debug, info, trace, warn};

// This is a load generator for testing server performance. This is not well written.
// Ignore this file. ;) Needs a lot of work.
//
// Todo
// * Receives need to be their own task/thread. The sync request/response loop in the load
//   generator doesn't actually test how fast the servers is, it only tests latency
// * Need to compensate for coordinated omission in measurement loop
// * Could track how out-of-order responses get
// * Make levels of response validation selectable

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
    pub fn display_loop(stats: Arc<Stats>) {
        let delay = Duration::from_secs(2);

        fn now() -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        }

        loop {
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

fn main() {
    let args = Args::parse();
    enable_logging(&args);
    debug!("command line: {:?}", args);

    let pub_key = if let Some(public_key) = args.public_key.as_ref() {
        let key = try_decode_key(public_key).unwrap();
        Some(key)
    } else {
        None
    };

    let stats = Arc::new(Stats::default());

    let mut threads = Vec::new();
    for idx in 0..args.num_workers {
        let args = args.clone();
        let stats = Arc::clone(&stats);

        threads.push(thread::spawn(move || run_worker(idx, args, pub_key, stats)));
    }

    threads.push(thread::spawn(move || {
        Stats::display_loop(Arc::clone(&stats))
    }));

    threads.into_iter().for_each(|w| w.join().unwrap());
}

fn run_worker(idx: usize, args: Args, _public_key: Option<PublicKey>, stats: Arc<Stats>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let source = UdpSocket::bind(addr).unwrap();

    // Don't wait too long to get response before declaring it a loss
    source
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();

    info!("worker {idx} starting, {source:?}");

    let nonce = Nonce::from(random_bytes::<32>());
    let request = Request::new(&nonce);
    let request_bytes = request.as_frame_bytes().unwrap();

    let target_addr: SocketAddr = format!("{}:{}", args.hostname, args.port).parse().unwrap();
    let mut buf = [0u8; 1024];

    for i in 0..args.num_requests {
        let n = source.send_to(&request_bytes, target_addr).unwrap();
        stats.num_sent.fetch_add(1, Relaxed);
        stats.bytes_sent.fetch_add(n, Relaxed);

        trace!("worker {idx} sent request {i}, {n} bytes");

        match source.recv_from(&mut buf) {
            Ok((n, _)) => {
                stats.num_responses.fetch_add(1, Relaxed);
                stats.bytes_received.fetch_add(n, Relaxed);
                trace!("worker {idx} received response {i}, {n} bytes")
            }
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                stats.num_timeouts.fetch_add(1, Relaxed);
                trace!("worker {idx} timed out waiting for response {i}")
            }
            Err(e) => {
                stats.num_errors.fetch_add(1, Relaxed);
                warn!("worker {idx} error waiting for response {i}: {e:?}");
            }
        }
    }
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
