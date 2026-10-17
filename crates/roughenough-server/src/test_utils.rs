//!
//! Provides "glue" needed for complex testing scenarios
//!

use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::SyncSender;
use std::time::Duration;

use mio::net::UdpSocket as MioUdpSocket;
use roughenough_common::clocksource::ClockSource;
use roughenough_keys::seed::MemoryBackend;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::{Nonce, ProtocolVersion, PublicKey};
use roughenough_protocol::{FromFrame, ToFrame};

use crate::args::Args;
use crate::keysource::KeySource;
use crate::metrics::aggregator::WorkerMetrics;
use crate::requests::RequestValidator;
use crate::responses::ResponseHandler;
use crate::worker::Worker;

#[allow(dead_code)]
pub struct TestContext {
    pub batch_size: u8,
    pub clock: ClockSource,
    pub response_handler: ResponseHandler,
    pub key_source: KeySource,
}

/// Creates a test ResponseHandler from a fixed seed and configuration
pub fn new_response_handler() -> ResponseHandler {
    TestContext::new(64).response_handler
}

/// The worker's request path without its sockets: validate, batch, and respond.
pub struct RequestPipeline {
    pub validator: RequestValidator,
    pub responder: ResponseHandler,
}

impl RequestPipeline {
    pub fn new(batch_size: u8) -> Self {
        let responder = TestContext::new(batch_size).response_handler;
        Self::with_responder(responder)
    }

    pub fn with_responder(responder: ResponseHandler) -> Self {
        let validator = RequestValidator::new(&responder.long_term_public_key());
        Self {
            validator,
            responder,
        }
    }

    pub fn collect(&mut self, bytes: &mut [u8], addr: SocketAddr) {
        if let Some((request, version)) = self.validator.validate(bytes) {
            self.responder.add_request(bytes, request, version, addr);
        }
    }

    /// Responds to every collected request and returns the responses.
    pub fn drain(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut responses = Vec::new();
        self.responder
            .process_responses(|addr, bytes| responses.push((addr, bytes.to_vec())));
        responses
    }
}

/// A worker bound to a loopback socket, not yet running.
pub struct TestWorker {
    pub worker: Worker,
    pub sock: MioUdpSocket,
    pub addr: SocketAddr,
    /// The responder's online key before the worker first runs
    pub initial_key: PublicKey,
}

/// Builds a worker from `args` whose key source uses `clock` and that
/// publishes metrics to `metrics`, bound to 127.0.0.1 on an ephemeral port.
pub fn test_worker(
    args: &Args,
    clock: ClockSource,
    metrics: SyncSender<WorkerMetrics>,
) -> TestWorker {
    let seed = Box::new(MemoryBackend::from_value(&[42u8; 32]));
    let key_source = KeySource::new(seed, clock, args.rotation_interval());
    let responder = ResponseHandler::new(args.batch_size, key_source);
    let initial_key = responder.public_key();
    let metrics_interval = Duration::from_secs(args.metrics_interval);
    let worker = Worker::new(0, responder, metrics, metrics_interval);

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
    // production bind_socket sets nonblocking; a blocking socket behind
    // MioUdpSocket::from_std would hang collect_requests instead of failing
    sock.set_nonblocking(true).expect("set_nonblocking");
    let addr = sock.local_addr().unwrap();

    TestWorker {
        worker,
        sock: MioUdpSocket::from_std(sock),
        addr,
        initial_key,
    }
}

/// Creates a TestContext so the midpoints of responses can be set to arbitrary values.
impl TestContext {
    pub fn new(batch_size: u8) -> Self {
        Self::new_at(batch_size, ClockSource::System.epoch_seconds())
    }

    /// Initializes the clock before issuing the response handler's delegation.
    pub fn new_at(batch_size: u8, epoch_seconds: u64) -> Self {
        let clock = ClockSource::new_mock(epoch_seconds);
        let seed = Box::new(MemoryBackend::from_value(&[42u8; 32]));
        let approx_90_days = Duration::from_secs(8_000_000);
        let key_source = KeySource::new(seed, clock.clone(), approx_90_days);
        let response_handler = ResponseHandler::new(batch_size, key_source.clone());

        TestContext {
            batch_size,
            clock,
            response_handler,
            key_source,
        }
    }

    #[allow(dead_code)]
    pub fn create_interaction_pair(&mut self, midpoint: u64) -> (Request, Response) {
        let mut val = [0u8; 32];
        aws_lc_rs::rand::fill(&mut val).expect("should be infallible");
        let nonce = Nonce::from(val);

        self.create_interaction_pair_with_nonce(midpoint, &nonce)
    }

    #[allow(dead_code)]
    pub fn create_interaction_pair_with_nonce(
        &mut self,
        midpoint: u64,
        nonce: &Nonce,
    ) -> (Request, Response) {
        self.clock.set_time(midpoint);

        let request = Request::new(nonce);
        let request_bytes = request.as_frame_bytes().unwrap();
        let sock_addr = "127.0.0.1:8080".parse().unwrap();

        self.response_handler.add_request(
            &request_bytes,
            request.clone(),
            ProtocolVersion::RFC,
            sock_addr,
        );

        let mut responses = Vec::new();

        self.response_handler
            .process_responses(|_addr, response_bytes| {
                let response = Response::from_frame_bytes(response_bytes).unwrap();
                responses.push(response);
            });
        assert_eq!(responses.len(), 1, "one response was generated");

        let response = responses.pop().unwrap();
        (request, response)
    }
}
