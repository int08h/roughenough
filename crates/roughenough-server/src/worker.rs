use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc::{Sender, SyncSender};
use std::time::Duration;

use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Poll, Token};
use roughenough_common::crypto::random_bytes;
use roughenough_protocol::util::ClockSource;
use tracing::info;

use crate::args::Args;
use crate::metrics::aggregator::WorkerMetrics;
use crate::network::CollectResult::Empty;
use crate::network::{CollectResult, NetworkHandler};
use crate::requests::RequestHandler;
use crate::responses::ResponseHandler;

/// Batches processed per wakeup before deadlines and the shutdown flag are re-checked.
const MAX_BATCHES_PER_WAKEUP: usize = 8;

/// Reports a worker thread's exit to the main thread. Held for the lifetime
/// of the worker closure so `Drop` runs on normal return AND panic unwind:
/// without it a panicked worker would leave the server silently serving at
/// reduced capacity.
pub struct ExitGuard {
    worker_id: usize,
    exit_channel: Sender<usize>,
}

impl ExitGuard {
    pub fn new(worker_id: usize, exit_channel: Sender<usize>) -> Self {
        Self {
            worker_id,
            exit_channel,
        }
    }
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        // The receiver disappears only when the main thread is already
        // exiting; there is nothing left to notify then
        let _ = self.exit_channel.send(self.worker_id);
    }
}

pub struct Worker {
    worker_id: usize,
    clock: ClockSource,
    net_handler: NetworkHandler,
    req_handler: RequestHandler,
    metrics_channel: SyncSender<WorkerMetrics>,
    key_replacement_interval: Duration,
    metrics_publish_interval: Duration,
    next_key_replacement: u64,
    next_metrics_publication: u64,
    /// Test-only: when the flag turns true the worker panics at the top of
    /// its next loop iteration, exercising the worker-death signal path
    #[cfg(feature = "test-utils")]
    test_panic_flag: Option<std::sync::Arc<AtomicBool>>,
}

impl Worker {
    pub fn new(
        worker_id: usize,
        args: Args,
        responder: ResponseHandler,
        clock: ClockSource,
        metrics_channel: SyncSender<WorkerMetrics>,
        metrics_interval: Duration,
    ) -> Self {
        let batch_size = args.batch_size as usize;
        let now = clock.epoch_seconds();

        Self {
            worker_id,
            clock,
            metrics_channel,
            net_handler: NetworkHandler::new(batch_size),
            req_handler: RequestHandler::new(responder),
            key_replacement_interval: args.rotation_interval(),
            metrics_publish_interval: metrics_interval,
            next_key_replacement: now,
            next_metrics_publication: now + metrics_interval.as_secs(),
            #[cfg(feature = "test-utils")]
            test_panic_flag: None,
        }
    }

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn set_test_panic_flag(&mut self, flag: std::sync::Arc<AtomicBool>) {
        self.test_panic_flag = Some(flag);
    }

    pub fn run(&mut self, mut sock: MioUdpSocket, keep_running: &AtomicBool) {
        const READER: Token = Token(0);

        let mut poll = Poll::new().expect("failed to create poll");

        poll.registry()
            .register(&mut sock, READER, mio::Interest::READABLE)
            .expect("failed to register socket");

        let mut events = Events::with_capacity(1024);
        let poll_duration = Duration::from_millis(350);

        let mut still_readable = false;

        while keep_running.load(Relaxed) {
            #[cfg(feature = "test-utils")]
            if let Some(flag) = &self.test_panic_flag
                && flag.load(Relaxed)
            {
                panic!("test-induced worker panic");
            }

            let now = self.clock.epoch_seconds();

            if now >= self.next_metrics_publication {
                self.publish_metrics();
            }

            if now >= self.next_key_replacement {
                self.replace_online_key();
            }

            if !still_readable {
                if poll.poll(&mut events, Some(poll_duration)).is_err() {
                    self.net_handler.record_failed_poll();
                }
                // single registered token: any event means the socket may be
                // readable
                still_readable = !events.is_empty();
            }

            if still_readable {
                for _ in 0..MAX_BATCHES_PER_WAKEUP {
                    let collect_result = self.collect_requests(&mut sock);

                    self.req_handler.generate_responses(|addr, bytes| {
                        self.net_handler.queue_response(bytes, addr);
                    });
                    self.net_handler.flush_responses(&mut sock);

                    if collect_result == Empty {
                        still_readable = false;
                        break;
                    }
                }
            }
        }
    }

    fn collect_requests(&mut self, sock: &mut MioUdpSocket) -> CollectResult {
        self.net_handler
            .collect_requests(sock, |request_bytes, src_addr| {
                self.req_handler.collect_request(request_bytes, src_addr);
            })
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
        let jitter = u64::from(random_bytes::<1>()[0]);
        self.next_key_replacement += self.key_replacement_interval.as_secs() - jitter;
    }

    fn publish_metrics(&mut self) {
        let snapshot = WorkerMetrics {
            worker_id: self.worker_id,
            network: self.net_handler.metrics(),
            request: self.req_handler.metrics(),
            response: self.req_handler.response_metrics(),
        };

        // Send snapshot, ignoring if channel is full
        let _ = self.metrics_channel.try_send(snapshot);

        // Reset metrics after sending
        self.net_handler.reset_metrics();
        self.req_handler.reset_metrics();

        // Schedule next publication
        let now = self.clock.epoch_seconds();
        self.next_metrics_publication = now + self.metrics_publish_interval.as_secs();
    }
}
