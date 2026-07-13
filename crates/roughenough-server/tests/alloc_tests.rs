//! Steady-state allocation proof for the mio worker loop.
//!
//! The divan benches profile only the CPU pipeline (collect/batch/sign),
//! never the poll/recv/send loop; this test drives the real loop through a
//! real socket and counts allocations on the worker thread only.
//!
//! After warmup, request parsing, batching, signing, response generation, and
//! the mio recv/send path must not use Rust's global allocator.
//!
//! Only one measurement test lives in this binary: the counters are global,
//! so concurrent measurement tests in one process would interfere.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::Ordering::{Relaxed, Release};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::thread;
use std::time::Duration;

use clap::Parser;
use mio::net::UdpSocket as MioUdpSocket;
use roughenough_keys::seed::MemoryBackend;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::Nonce;
use roughenough_protocol::util::ClockSource;
use roughenough_protocol::wire::ToFrame;
use roughenough_server::args::Args;
use roughenough_server::keysource::KeySource;
use roughenough_server::responses::ResponseHandler;
use roughenough_server::worker::Worker;

static WINDOW_ALLOCS: AtomicUsize = AtomicUsize::new(0);
static WINDOW_OPEN: AtomicBool = AtomicBool::new(false);

thread_local! {
    // const-initialized and Drop-free so touching it inside the allocator
    // cannot itself allocate
    static ON_WORKER_THREAD: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator;

impl CountingAllocator {
    // counting is scoped to the worker thread AND the measurement window;
    // the test harness and client threads allocate freely
    fn record(&self) {
        if WINDOW_OPEN.load(Relaxed) && ON_WORKER_THREAD.with(|c| c.get()) {
            WINDOW_ALLOCS.fetch_add(1, Relaxed);
        }
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.record();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.record();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.record();
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const WARMUP_PACKETS: usize = 1000;
const MEASURED_PACKETS: usize = 4000;

/// Closed-loop driver: one request in flight at a time, so batches are
/// always size 1 and nothing is dropped to a full receive buffer.
fn drive(client: &UdpSocket, server: SocketAddr, request: &[u8], count: usize) -> usize {
    let mut buf = [0u8; 1500];
    let mut received = 0;
    for _ in 0..count {
        client.send_to(request, server).unwrap();
        if client.recv_from(&mut buf).is_ok() {
            received += 1;
        }
    }
    received
}

#[test]
fn mio_loop_steady_state_is_allocation_free() {
    let keep_running = AtomicBool::new(true);
    let (tx, _rx) = std::sync::mpsc::sync_channel(4);

    let mut args = Args::try_parse_from(["roughenough_server"]).unwrap();
    // deadline work allocates (a metrics snapshot clones a Vec-bearing
    // struct; rotation regenerates the online key): pin both far beyond the
    // measurement window. Rotation still fires once at startup, inside
    // warmup.
    args.metrics_interval = 3600;
    args.rotation_interval = 24;
    args.batch_size = 1;

    let seed = Box::new(MemoryBackend::from_value(&[42u8; 32]));
    let key_source = KeySource::new(seed, ClockSource::System, args.rotation_interval());
    let responder = ResponseHandler::new(args.batch_size, key_source);
    let metrics_interval = Duration::from_secs(args.metrics_interval);
    let mut worker = Worker::new(
        0,
        args,
        responder,
        ClockSource::System,
        tx,
        metrics_interval,
    );

    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
    sock.set_nonblocking(true).expect("set_nonblocking");
    let server_addr = sock.local_addr().unwrap();
    let sock = MioUdpSocket::from_std(sock);

    // prebuilt before the window so request construction is never counted
    let request = Request::new(&Nonce::from([9u8; 32]))
        .as_frame_bytes()
        .unwrap();

    thread::scope(|s| {
        let worker_thread = s.spawn(|| {
            ON_WORKER_THREAD.with(|c| c.set(true));
            worker.run(sock, &keep_running)
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let warmed = drive(&client, server_addr, &request, WARMUP_PACKETS);
        assert!(warmed > WARMUP_PACKETS / 2, "warmup got {warmed} responses");

        WINDOW_ALLOCS.store(0, Relaxed);
        WINDOW_OPEN.store(true, Release);
        let received = drive(&client, server_addr, &request, MEASURED_PACKETS);
        WINDOW_OPEN.store(false, Release);

        keep_running.store(false, Release);
        worker_thread.join().expect("worker thread panicked");

        assert!(
            received >= MEASURED_PACKETS / 2,
            "measurement invalid: only {received} of {MEASURED_PACKETS} responses"
        );

        let allocs = WINDOW_ALLOCS.load(Relaxed);
        assert_eq!(
            allocs, 0,
            "steady-state allocations regressed while serving \
             {MEASURED_PACKETS} datagrams"
        );
    });
}
