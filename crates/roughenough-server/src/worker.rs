use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use roughenough_protocol::util::ClockSource;
use roughenough_server::args::Args;
use roughenough_server::backend::{CollectResult, NetworkBackend};
use roughenough_server::metrics::aggregator::WorkerMetrics;
use roughenough_server::requests::RequestHandler;
use roughenough_server::responses::ResponseHandler;
use tracing::info;

/// Worker thread that processes Roughtime requests using a pluggable network backend.
///
/// Each worker owns its own backend instance and operates independently.
/// The backend abstracts the network I/O strategy (mio, recvmmsg, etc.).
pub struct Worker<B: NetworkBackend> {
    worker_id: usize,
    clock: ClockSource,
    backend: B,
    req_handler: RequestHandler,
    metrics_channel: Sender<WorkerMetrics>,
    key_replacement_interval: Duration,
    metrics_publish_interval: Duration,
    next_key_replacement: u64,
    next_metrics_publication: u64,
}

impl<B: NetworkBackend> Worker<B> {
    /// Create a new Worker with the given backend.
    ///
    /// The backend should already be initialized with a bound socket.
    pub fn new(
        worker_id: usize,
        args: Args,
        responder: ResponseHandler,
        clock: ClockSource,
        metrics_channel: Sender<WorkerMetrics>,
        metrics_interval: Duration,
        backend: B,
    ) -> Self {
        let now = clock.epoch_seconds();

        Self {
            worker_id,
            clock,
            backend,
            metrics_channel,
            req_handler: RequestHandler::new(responder),
            key_replacement_interval: args.rotation_interval(),
            metrics_publish_interval: metrics_interval,
            next_key_replacement: now,
            next_metrics_publication: now + metrics_interval.as_secs(),
        }
    }

    /// Run the worker's main event loop.
    ///
    /// Processes requests until `keep_running` becomes false.
    pub fn run(&mut self, keep_running: &AtomicBool) {
        let poll_duration = Duration::from_millis(350);

        while keep_running.load(Relaxed) {
            let now = self.clock.epoch_seconds();

            if now >= self.next_metrics_publication {
                self.publish_metrics();
            }

            if now >= self.next_key_replacement {
                self.replace_online_key();
            }

            if self.backend.wait_for_events(poll_duration) {
                loop {
                    let collect_result =
                        self.backend.collect_requests(|request_bytes, src_addr| {
                            self.req_handler.collect_request(request_bytes, src_addr);
                        });

                    // Time the full batch processing including all I/O
                    let timer = Instant::now();

                    let batch_size = self.req_handler.generate_responses(|addr, bytes| {
                        self.backend.send_response(bytes, addr);
                    });

                    // Flush any pending sends after response generation
                    self.backend.flush();

                    // Record timing for the complete batch (CPU + send I/O)
                    if let Some(batch_size) = batch_size {
                        self.req_handler
                            .record_batch_timing(batch_size, timer.elapsed());
                    }

                    if collect_result == CollectResult::Empty {
                        break;
                    }
                }
            }
        }
    }

    fn replace_online_key(&mut self) {
        self.req_handler.replace_online_key();

        info!(
            "worker-{}, online key {:?}",
            self.worker_id,
            self.req_handler.public_key()
        );

        // jitter so that all worker threads don't thundering herd and replace their
        // keys at the same time, stalling all responses
        let jitter = fastrand::u8(0..u8::MAX) as u64;
        self.next_key_replacement += self.key_replacement_interval.as_secs() - jitter;
    }

    fn publish_metrics(&mut self) {
        let snapshot = WorkerMetrics {
            worker_id: self.worker_id,
            network: self.backend.metrics(),
            request: self.req_handler.metrics(),
            response: self.req_handler.response_metrics(),
        };

        // Send snapshot, ignoring if channel is full
        let _ = self.metrics_channel.try_send(snapshot);

        // Reset metrics after sending
        self.backend.reset_metrics();
        self.req_handler.reset_metrics();

        // Schedule next publication
        let now = self.clock.epoch_seconds();
        self.next_metrics_publication = now + self.metrics_publish_interval.as_secs();
    }
}
