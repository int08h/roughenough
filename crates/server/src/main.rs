//!
//! # Server Operating Model
//!
//! - **Multi-threaded**: Spawns one worker thread per CPU core. All threads bind to the same UDP
//!   port using `SO_REUSEPORT`, letting the kernel load-balance incoming packets across threads.
//!
//! - **Event-driven I/O**: Each thread runs an independent mio event loop (poll-based) to handle
//!   non-blocking UDP I/O. No async/await - just a simple synchronous event loop.
//!
//! - **Zero shared state**: Each thread is completely independent with its own online key,
//!   socket, and processing pipeline. No synchronization or sharing between threads.
//!
//! - **Request Batching**: Each thread collects up to 64 requests, builds a Merkle tree, signs
//!   the root once, then sends responses to each client. This amortizes the (relatively)
//!   expensive Ed25519 signature calculation across all requests in a batch.
//!
//! - **Processing Pipeline**: UDP Socket -> NetworkHandler -> RequestHandler -> BatchingResponder
//!   -> UDP Socket
//!
mod worker;

use std::io;
use std::net::UdpSocket as StdUdpSocket;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Release;
use std::thread::JoinHandle;
use std::time::Duration;

use clap::Parser;
use crossbeam_channel::{Sender, bounded};
use keys::seed::{Seed, SeedBackend, try_choose_backend};
use keys::storage::try_load_seed_sync;
use mio::net::UdpSocket as MioUdpSocket;
use protocol::util::ClockSource;
use server::args::Args;
use server::keysource::KeySource;
use server::metrics::aggregator::{MetricsAggregator, WorkerMetrics};
use server::metrics::snapshot::validate_metrics_directory;
use server::responses::ResponseHandler;
use socket2::{Domain, Socket, Type};
use tracing::{debug, error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, filter};
use worker::Worker;

/// Global flag that will be set to `false` when all threads should exit.
static KEEP_RUNNING: AtomicBool = AtomicBool::new(true);

fn main() {
    set_ctrlc_handler();

    let args = Args::parse();
    enable_logging(&args);
    debug!("{args:?}");

    let clock = choose_clock(&args);
    let seed = load_seed(&args);
    let key_source = KeySource::new(
        args.version(),
        seed,
        clock.clone(),
        args.rotation_interval(),
    );

    info!("Long term public key: {:?}", key_source.public_key());

    let (metrics_thread, metrics_chan_tx) =
        start_metrics_thread(&args, clock.clone(), &KEEP_RUNNING);

    let mut threads = Vec::new();
    threads.push(metrics_thread);

    for i in 0..args.num_threads {
        let args = args.clone();
        let clock = clock.clone();
        let ks = key_source.clone();
        let metrics_chan_tx = metrics_chan_tx.clone();

        let thread = std::thread::Builder::new()
            .name(format!("worker-{i}"))
            .spawn(move || worker_task(i, ks, args, clock, metrics_chan_tx))
            .unwrap();

        threads.push(thread);
    }

    for thread in threads {
        thread.join().unwrap()
    }

    info!("Server finished");
}

fn load_seed(args: &Args) -> Box<dyn SeedBackend> {
    let seed = if args.seed.is_empty() {
        warn!("--seed is empty, using all zero seed");
        Seed::new(&[0u8; 32])
    } else {
        try_load_seed_sync(&args.seed).unwrap_or_else(|e| panic!("loading seed: {e}"))
    };

    let mut backend = try_choose_backend(&args.seed_backend.to_string())
        .unwrap_or_else(|e| panic!("choosing seed backend: {e}"));

    info!(
        "Loaded {}-byte seed into '{}' backend",
        seed.len(),
        &args.seed_backend
    );

    backend.store_seed(seed).unwrap();
    backend
}

fn choose_clock(args: &Args) -> ClockSource {
    match args.fixed_offset {
        0 => ClockSource::System,
        offset => ClockSource::FixedOffset(offset),
    }
}

fn worker_task(
    idx: u16,
    key_source: KeySource,
    args: Args,
    clock: ClockSource,
    metrics_channel: Sender<WorkerMetrics>,
) {
    let sock = bind_socket(&args).expect("Failed to bind socket");
    let responder = ResponseHandler::new(args.batch_size, key_source);
    let metrics_interval = Duration::from_secs(args.metrics_interval);
    let idx = idx as usize;

    let mut worker = Worker::new(
        idx,
        args,
        responder,
        clock,
        metrics_channel,
        metrics_interval,
    );
    worker.run(sock, &KEEP_RUNNING);
}

// Bind to the server port using SO_REUSEPORT and SO_REUSEADDR so the kernel will fairly
// balance traffic to each worker. https://lwn.net/Articles/542629/
fn bind_socket(args: &Args) -> io::Result<MioUdpSocket> {
    let sock_addr = args.udp_socket_addr();
    let sock_domain = Domain::for_address(sock_addr);
    let socket = Socket::new(sock_domain, Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&sock_addr.into())?;

    let std_socket: StdUdpSocket = socket.into();
    let mio_socket: MioUdpSocket = MioUdpSocket::from_std(std_socket);
    Ok(mio_socket)
}

fn set_ctrlc_handler() {
    ctrlc::set_handler(|| {
        info!("Received Ctrl-C, exiting...");
        KEEP_RUNNING.store(false, Release);
    })
    .expect("Error setting Ctrl-C handler");
}

fn enable_logging(args: &Args) {
    // AWS, GCP, Rustls, Hyper, etc crates are quite verbose, "normal" level for them is WARN
    let cloud_sdk_verbosity = match args.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        3.. => tracing::Level::TRACE,
    };

    let verbosity = match args.verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        2.. => tracing::Level::TRACE,
    };

    let filters = filter::Targets::new()
        .with_target("aws_config", cloud_sdk_verbosity)
        .with_target("aws_sdk_kms", cloud_sdk_verbosity)
        .with_target("aws_sdk_secretsmanager", cloud_sdk_verbosity)
        .with_target("google_cloud_kms_v1", cloud_sdk_verbosity)
        .with_target("google_cloud_secretmanager_v1", cloud_sdk_verbosity)
        .with_target("hyper_util", cloud_sdk_verbosity)
        .with_target("rustls", cloud_sdk_verbosity)
        .with_default(verbosity); // for all other targets

    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_filter(filters);

    tracing_subscriber::registry().with(fmt_layer).init();
}

/// Creates metrics collection infrastructure and spawns collector thread
pub fn start_metrics_thread(
    args: &Args,
    clock: ClockSource,
    keep_running: &'static AtomicBool,
) -> (JoinHandle<()>, Sender<WorkerMetrics>) {
    let num_workers = args.num_threads as usize;
    let metrics_interval = Duration::from_secs(args.metrics_interval);

    let metrics_path = args.metrics_output.as_ref().map(|metrics_path_arg| {
        let path = Path::new(metrics_path_arg);
        if let Err(e) = validate_metrics_directory(path) {
            error!("metrics path: {e}");
            std::process::exit(1);
        }
        info!("Metrics will be written to: {}", path.display());
        path.to_path_buf()
    });

    // Each worker pushes at most once per interval, so num_workers * 2 should be plenty
    let (sender, receiver) = bounded(num_workers * 2);

    let collector = MetricsAggregator::new(
        receiver,
        num_workers,
        metrics_interval,
        keep_running,
        clock,
        metrics_path,
    );

    let thread = std::thread::Builder::new()
        .name("metrics-collector".to_string())
        .spawn(move || collector.run())
        .expect("Failed to spawn metrics collector thread");

    (thread, sender)
}
