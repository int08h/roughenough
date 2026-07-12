//! In-process tests that drive the mio worker loop end to end: bind a real
//! UDP socket, run `Worker::run` on a scoped thread, and talk to it as a
//! client. This is the first direct coverage of the worker loop itself; the
//! shutdown tests lock in the 350ms-quantum shutdown latency and the
//! bounded-drain guarantee under flood.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Acquire, Release};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use crossbeam_channel::{Sender, bounded};
use mio::net::UdpSocket as MioUdpSocket;
use roughenough_keys::seed::MemoryBackend;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::Nonce;
use roughenough_protocol::util::ClockSource;
use roughenough_protocol::{FromFrame, ToFrame};
use roughenough_server::args::Args;
use roughenough_server::keysource::KeySource;
use roughenough_server::metrics::aggregator::WorkerMetrics;
use roughenough_server::responses::ResponseHandler;
use roughenough_server::worker::Worker;

// parsed rather than a struct literal so future Args fields don't break this
fn test_args() -> Args {
    Args::try_parse_from(["roughenough_server"]).expect("default args parse")
}

fn new_worker(args: Args, tx: Sender<WorkerMetrics>) -> (Worker, MioUdpSocket, SocketAddr) {
    let seed = Box::new(MemoryBackend::from_value(&[42u8; 32]));
    let key_source = KeySource::new(seed, ClockSource::System, args.rotation_interval());
    let responder = ResponseHandler::new(args.batch_size, key_source);
    let metrics_interval = Duration::from_secs(args.metrics_interval);

    let worker = Worker::new(
        0,
        args,
        responder,
        ClockSource::System,
        tx,
        metrics_interval,
    );

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
    // production bind_socket sets nonblocking; a blocking socket behind
    // MioUdpSocket::from_std would hang collect_requests instead of failing
    sock.set_nonblocking(true).expect("set_nonblocking");
    let addr = sock.local_addr().unwrap();

    (worker, MioUdpSocket::from_std(sock), addr)
}

fn request_bytes(nonce_value: u8) -> Vec<u8> {
    let nonce = Nonce::from([nonce_value; 32]);
    Request::new(&nonce).as_frame_bytes().unwrap()
}

#[test]
fn worker_answers_request_end_to_end() {
    let keep_running = AtomicBool::new(true);
    let (tx, _rx) = bounded(4);
    let (mut worker, sock, server_addr) = new_worker(test_args(), tx);

    thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        // UDP delivery is best-effort even on loopback: retry a few times
        let mut reply = None;
        for attempt in 0..4 {
            client
                .send_to(&request_bytes(attempt), server_addr)
                .unwrap();
            let mut buf = [0u8; 1500];
            if let Ok((nbytes, _)) = client.recv_from(&mut buf) {
                reply = Some(buf[..nbytes].to_vec());
                break;
            }
        }

        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");

        let mut reply = reply.expect("no response from worker");
        let mut cursor = ParseCursor::new(&mut reply);
        Response::from_frame(&mut cursor).expect("reply must parse as a Response");
    });
}

#[test]
fn worker_shuts_down_promptly() {
    let keep_running = AtomicBool::new(true);
    let (tx, _rx) = bounded(4);
    let (mut worker, sock, _server_addr) = new_worker(test_args(), tx);

    thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));

        // let the worker enter its poll loop
        thread::sleep(Duration::from_millis(100));

        let start = Instant::now();
        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");

        // one 350ms poll quantum plus generous slack
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "shutdown took {elapsed:?}"
        );
    });
}

#[test]
fn worker_shuts_down_under_load() {
    let keep_running = AtomicBool::new(true);
    let stop_senders = AtomicBool::new(false);
    let (tx, _rx) = bounded(4);
    let (mut worker, sock, server_addr) = new_worker(test_args(), tx);

    thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));

        for i in 0..2u8 {
            let stop_senders = &stop_senders;
            s.spawn(move || {
                let client = UdpSocket::bind("127.0.0.1:0").unwrap();
                let bytes = request_bytes(i);
                while !stop_senders.load(Acquire) {
                    let _ = client.send_to(&bytes, server_addr);
                }
            });
        }

        // let the flood establish so the socket never drains
        thread::sleep(Duration::from_millis(300));

        let start = Instant::now();
        keep_running.store(false, Release);
        // stop the senders before unwrapping: a worker panic must fail the
        // test, not leave the scoped sender threads spinning forever
        let join_result = worker_thread.join();
        let elapsed = start.elapsed();
        stop_senders.store(true, Release);
        join_result.expect("worker thread panicked");

        // the bounded drain re-checks the shutdown flag at least every
        // MAX_BATCHES_PER_WAKEUP batches even though the socket stays full
        assert!(
            elapsed < Duration::from_secs(2),
            "shutdown under load took {elapsed:?}"
        );
    });
}

#[test]
fn worker_publishes_metrics() {
    let keep_running = AtomicBool::new(true);
    let (tx, rx) = bounded::<WorkerMetrics>(4);
    let mut args = test_args();
    args.metrics_interval = 1;
    let (mut worker, sock, server_addr) = new_worker(args, tx);

    thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();

        // keep requests flowing until some snapshot reflects one; snapshots
        // reset counters after each publication, so poll repeatedly
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut saw_request = false;
        while Instant::now() < deadline && !saw_request {
            client.send_to(&request_bytes(1), server_addr).unwrap();
            if let Ok(snapshot) = rx.recv_timeout(Duration::from_millis(250))
                && snapshot.request.num_ok_requests >= 1
            {
                saw_request = true;
            }
        }

        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");

        assert!(saw_request, "no metrics snapshot contained the request");
    });
}
