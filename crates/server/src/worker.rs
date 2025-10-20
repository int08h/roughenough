use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use crossbeam_channel::Sender;
use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Poll, Token};
use protocol::util::ClockSource;
use server::args::Args;
use server::metrics::aggregator::WorkerMetrics;
use server::network::CollectResult::Empty;
use server::network::{CollectResult, NetworkHandler};
use server::requests::RequestHandler;
use server::responses::ResponseHandler;
use tracing::info;

pub struct Worker {
    worker_id: usize,
    clock: ClockSource,
    net_handler: NetworkHandler,
    req_handler: RequestHandler,
    metrics_channel: Sender<WorkerMetrics>,
    key_replacement_interval: Duration,
    metrics_publish_interval: Duration,
    next_key_replacement: u64,
    next_metrics_publication: u64,
}

impl Worker {
    pub fn new(
        worker_id: usize,
        args: Args,
        responder: ResponseHandler,
        clock: ClockSource,
        metrics_channel: Sender<WorkerMetrics>,
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
        }
    }

    pub fn run(&mut self, mut sock: MioUdpSocket, keep_running: &AtomicBool) {
        const READER: Token = Token(0);

        let mut poll = Poll::new().expect("failed to create poll");

        poll.registry()
            .register(&mut sock, READER, mio::Interest::READABLE)
            .expect("failed to register socket");

        let mut events = Events::with_capacity(1024);
        let poll_duration = Duration::from_millis(350);

        while keep_running.load(Relaxed) {
            let now = self.clock.epoch_seconds();

            if now >= self.next_metrics_publication {
                self.publish_metrics();
            }

            if now >= self.next_key_replacement {
                self.replace_online_key();
            }

            if poll.poll(&mut events, Some(poll_duration)).is_err() {
                self.net_handler.record_failed_poll();
            }

            for event in &events {
                match event.token() {
                    READER => loop {
                        let collect_result = self.collect_requests(&mut sock);

                        self.req_handler.generate_responses(|addr, bytes| {
                            self.net_handler.send_response(&mut sock, bytes, addr);
                        });

                        if collect_result == Empty {
                            break;
                        }
                    },
                    _ => unreachable!(),
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
        let jitter = fastrand::u8(0..u8::MAX) as u64;
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
