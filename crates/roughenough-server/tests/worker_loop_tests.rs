//! In-process tests that drive the mio worker loop end to end: bind a real
//! UDP socket, run `Worker::run` on a scoped thread, and talk to it as a
//! client. This is the first direct coverage of the worker loop itself; the
//! shutdown tests lock in the 350ms-quantum shutdown latency and the
//! bounded-drain guarantee under flood.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Acquire, Release};
use std::sync::mpsc::{channel, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use roughenough_common::clocksource::ClockSource;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::{Nonce, PublicKey};
use roughenough_protocol::{FromFrame, ToFrame};
use roughenough_server::args::Args;
use roughenough_server::metrics::aggregator::WorkerMetrics;
use roughenough_server::test_utils::{TestWorker, test_worker};
use roughenough_server::worker::ExitGuard;

// parsed rather than a struct literal so future Args fields don't break this
fn test_args() -> Args {
    Args::try_parse_from(["roughenough_server", "--insecure-zero-seed"])
        .expect("default args parse")
}

fn request_bytes(nonce_value: u8) -> Vec<u8> {
    let nonce = Nonce::from([nonce_value; 32]);
    Request::new(&nonce).as_frame_bytes().unwrap()
}

/// Send requests until one is answered; None if every attempt times out
fn exchange(server_addr: SocketAddr) -> Option<Vec<u8>> {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // UDP delivery is best-effort even on loopback: retry a few times
    for attempt in 0..4 {
        client
            .send_to(&request_bytes(attempt), server_addr)
            .unwrap();
        let mut buf = [0u8; 1500];
        if let Ok((nbytes, _)) = client.recv_from(&mut buf) {
            return Some(buf[..nbytes].to_vec());
        }
    }
    None
}

/// Longer than the worker's 350ms poll timeout, so it re-checks the clock
const LOOP_QUANTUM: Duration = Duration::from_millis(800);

/// The online key that signed `reply`, checking that the key's delegation
/// covers the response midpoint as clients require (RFC 5.2.5)
fn signing_key(reply: Option<Vec<u8>>) -> PublicKey {
    let mut reply = reply.expect("no response from worker");
    let response = Response::from_frame(&mut ParseCursor::new(&mut reply)).unwrap();
    let dele = response.cert().dele();
    let midp = response.srep().midp();
    assert!(
        (dele.mint()..=dele.maxt()).contains(&midp),
        "MIDP {midp} outside delegation [{}, {}]",
        dele.mint(),
        dele.maxt()
    );
    *dele.pubk()
}

#[test]
fn worker_answers_request_end_to_end() {
    let keep_running = AtomicBool::new(true);
    let (tx, _rx) = sync_channel(4);
    let TestWorker {
        mut worker,
        sock,
        addr: server_addr,
        ..
    } = test_worker(&test_args(), ClockSource::System, tx);

    thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));
        let reply = exchange(server_addr);

        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");

        let mut reply = reply.expect("no response from worker");
        let mut cursor = ParseCursor::new(&mut reply);
        Response::from_frame(&mut cursor).expect("reply must parse as a Response");
    });
}

#[test]
fn worker_does_not_replace_online_key_at_startup() {
    // Each online key costs a long-term-key signature, which may be an HSM
    // or remote KMS call; the responder's initial key must be used as-is
    let keep_running = AtomicBool::new(true);
    let (tx, _rx) = sync_channel(4);
    let TestWorker {
        mut worker,
        sock,
        addr: server_addr,
        initial_key,
        ..
    } = test_worker(&test_args(), ClockSource::System, tx);

    let reply = thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));
        let reply = exchange(server_addr);

        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");
        reply
    });

    assert_eq!(signing_key(reply), initial_key);
}

#[test]
fn worker_rotates_online_key_after_backward_clock_step() {
    // A key minted before the step has MINT after the new time, so clients
    // reject its responses until the worker rotates
    let keep_running = AtomicBool::new(true);
    let start = ClockSource::System.epoch_seconds();
    let mut clock = ClockSource::new_mock(start);
    let (tx, _rx) = sync_channel(4);
    let TestWorker {
        mut worker,
        sock,
        addr: server_addr,
        initial_key,
        ..
    } = test_worker(&test_args(), clock.clone(), tx);

    let [before, after] = thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));
        let before = exchange(server_addr);

        clock.set_time(start - 7_200);
        thread::sleep(LOOP_QUANTUM);
        let after = exchange(server_addr);

        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");
        [before, after]
    });

    assert_eq!(signing_key(before), initial_key);
    assert_ne!(signing_key(after), initial_key);
}

#[test]
fn worker_rotates_once_after_forward_clock_jump() {
    // A jump of many rotation intervals needs one new key, not one per
    // interval skipped
    let keep_running = AtomicBool::new(true);
    let start = ClockSource::System.epoch_seconds();
    let mut clock = ClockSource::new_mock(start);
    let (tx, _rx) = sync_channel(4);
    let TestWorker {
        mut worker,
        sock,
        addr: server_addr,
        initial_key,
        ..
    } = test_worker(&test_args(), clock.clone(), tx);

    let [first, second] = thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));

        clock.set_time(start + 10 * 86_400);
        thread::sleep(LOOP_QUANTUM);
        let first = exchange(server_addr);
        thread::sleep(LOOP_QUANTUM);
        let second = exchange(server_addr);

        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");
        [first, second]
    });

    let first = signing_key(first);
    assert_ne!(first, initial_key);
    assert_eq!(signing_key(second), first);
}

#[test]
fn worker_shuts_down_promptly() {
    let keep_running = AtomicBool::new(true);
    let (tx, _rx) = sync_channel(4);
    let TestWorker {
        mut worker, sock, ..
    } = test_worker(&test_args(), ClockSource::System, tx);

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
    let (tx, _rx) = sync_channel(4);
    let TestWorker {
        mut worker,
        sock,
        addr: server_addr,
        ..
    } = test_worker(&test_args(), ClockSource::System, tx);

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
fn exit_guard_reports_worker_panic() {
    let (exit_tx, exit_rx) = channel();

    thread::scope(|s| {
        // same shape as main(): the guard's Drop runs during the panic
        // unwind and reports the death to the monitoring channel
        let guarded = s.spawn(move || {
            let _guard = ExitGuard::new(7, exit_tx);
            panic!("injected");
        });

        let exit_signal = exit_rx.recv_timeout(Duration::from_secs(2));
        assert_eq!(exit_signal, Ok(7));
        // consume the panic so the scope does not re-raise it
        assert!(guarded.join().is_err(), "thread should have panicked");
    });
}

#[test]
fn exit_guard_reports_normal_exit() {
    let (exit_tx, exit_rx) = channel();

    thread::scope(|s| {
        let guarded = s.spawn(move || {
            let _guard = ExitGuard::new(7, exit_tx);
        });

        let exit_signal = exit_rx.recv_timeout(Duration::from_secs(2));
        assert_eq!(exit_signal, Ok(7));
        guarded.join().expect("thread panicked");
    });
}

#[test]
fn worker_publishes_metrics() {
    let keep_running = AtomicBool::new(true);
    let mut args = test_args();
    args.metrics_interval = 1;
    let (tx, rx) = sync_channel(4);
    let TestWorker {
        mut worker,
        sock,
        addr: server_addr,
        ..
    } = test_worker(&args, ClockSource::System, tx);

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

#[test]
fn worker_metrics_survive_full_channel() {
    let keep_running = AtomicBool::new(true);
    let (tx, rx) = sync_channel::<WorkerMetrics>(1);
    let mut args = test_args();
    args.metrics_interval = 1;

    // fill the channel so the worker's first publish finds it full
    tx.send(WorkerMetrics {
        worker_id: 99,
        network: Default::default(),
        request: Default::default(),
        response: Default::default(),
    })
    .unwrap();

    let TestWorker {
        mut worker,
        sock,
        addr: server_addr,
        ..
    } = test_worker(&args, ClockSource::System, tx.clone());

    let snapshots: Vec<WorkerMetrics> = thread::scope(|s| {
        let worker_thread = s.spawn(|| worker.run(sock, &keep_running));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        // exactly two answered requests, so the expected count is exactly 2
        for i in 0..2u8 {
            client.send_to(&request_bytes(i), server_addr).unwrap();
            let mut buf = [0u8; 1500];
            if let Err(e) = client.recv_from(&mut buf) {
                panic!("no reply to request {i}: {e}");
            }
        }

        // the worker publishes into the full channel and that snapshot is dropped
        thread::sleep(Duration::from_millis(1500));

        let dummy = rx.recv().unwrap();
        assert_eq!(dummy.worker_id, 99);

        // the channel has room now, so the next publish succeeds
        thread::sleep(Duration::from_millis(1500));

        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");

        rx.try_iter().collect()
    });

    let num_ok: usize = snapshots
        .iter()
        .filter(|m| m.worker_id != 99)
        .map(|m| m.request.num_ok_requests)
        .sum();

    assert_eq!(num_ok, 2, "ok requests summed over published snapshots");
}
