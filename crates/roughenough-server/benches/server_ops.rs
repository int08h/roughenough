use std::net::SocketAddr;
use std::time::Duration;

use divan::counter::BytesCount;
use divan::{AllocProfiler, Bencher};
use roughenough_keys::seed::MemoryBackend;
use roughenough_protocol::ToFrame;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::{Nonce, ProtocolVersion};
use roughenough_protocol::util::ClockSource;
use roughenough_server::args::{Args, SeedBackendArg};
use roughenough_server::keysource::KeySource;
use roughenough_server::requests::RequestHandler;
use roughenough_server::responses::ResponseHandler;

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

fn create_wire_request(nonce_value: u8) -> Vec<u8> {
    let nonce = Nonce::from([nonce_value; 32]);
    let request = Request::new(&nonce);

    request.as_frame_bytes().unwrap()
}

fn create_wire_request_with_version(nonce_value: u8, version: ProtocolVersion) -> Vec<u8> {
    let nonce = Nonce::from([nonce_value; 32]);
    let request = Request::new_with_versions(&nonce, &[version]);

    request.as_frame_bytes().unwrap()
}

fn create_request_handler() -> RequestHandler {
    let args = Args {
        batch_size: 64,
        interface: "0.0.0.0".parse().unwrap(),
        port: 2002,
        num_threads: 1,
        fixed_offset: 0,
        quiet: false,
        rotation_interval: 1,
        metrics_interval: 60,
        seed: "".to_string(),
        insecure_zero_seed: false,
        seed_backend: SeedBackendArg::Memory,
        verbose: 0,
        metrics_output: None,
    };

    let seed = Box::new(MemoryBackend::from_random());
    let ks = KeySource::new(seed, ClockSource::System, Duration::from_secs(60));
    let responder = ResponseHandler::new(args.batch_size, ks);

    RequestHandler::new(responder)
}

mod network_send {
    use mio::net::UdpSocket as MioUdpSocket;
    use roughenough_server::network::NetworkHandler;

    use super::*;

    /// Deliver one batch of responses to a loopback peer that never reads
    /// (UDP drops silently when the peer queue fills, so sends stay cheap and
    /// uniform). Measures the per-batch syscall cost of the send path.
    #[divan::bench(
        min_time = 0.250,
        args = [16, 32, 64],
    )]
    fn send_batch(bencher: Bencher, batch_size: usize) {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let mut server = MioUdpSocket::from_std(server);

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr: SocketAddr = peer.local_addr().unwrap();

        let mut handler = NetworkHandler::new(batch_size);
        // typical framed response size for a depth-6 PATH
        let payload = [0u8; 600];

        bencher
            .counter(BytesCount::new(payload.len() * batch_size))
            .bench_local(move || {
                for _ in 0..batch_size {
                    handler.queue_response(&payload, peer_addr);
                }
                handler.flush_responses(&mut server);
            });
    }
}

mod request_handler {
    use std::hint::black_box;

    use super::*;

    #[divan::bench(
        min_time = 0.250,
        args = [1, 2, 4, 8, 16, 32, 64],
    )]
    fn batch_processing(bencher: Bencher, batch_size: usize) {
        let mut handler = create_request_handler();

        // Create a pool of request bytes and addresses that we'll reuse
        let mut request_pool: Vec<Vec<u8>> = (0..batch_size)
            .map(|i| create_wire_request(i as u8))
            .collect();

        let addrs: Vec<SocketAddr> = (0..batch_size)
            .map(|i| format!("127.0.0.1:{}", 8080 + i).parse().unwrap())
            .collect();

        let total_bytes = request_pool.iter().map(|r| r.len()).sum::<usize>();

        bencher
            .counter(BytesCount::new(total_bytes))
            .bench_local(move || {
                for (request_bytes, addr) in request_pool.iter_mut().zip(addrs.iter()) {
                    handler.collect_request(request_bytes, *addr);
                }

                let mut byte_count = 0;
                handler.generate_responses(|_addr, bytes| {
                    byte_count += bytes.len();
                });

                black_box(byte_count)
            });
    }

    /// Worst case for version negotiation: clients alternate between the two
    /// supported versions, so each batch performs two SREP signatures instead
    /// of one. Compare with `batch_processing` for the inherent cost.
    #[divan::bench(
        min_time = 0.250,
        args = [2, 64],
    )]
    fn mixed_version_batch_processing(bencher: Bencher, batch_size: usize) {
        let mut handler = create_request_handler();

        let mut request_pool: Vec<Vec<u8>> = (0..batch_size)
            .map(|i| {
                let version = if i % 2 == 0 {
                    ProtocolVersion::DRAFT
                } else {
                    ProtocolVersion::RFC
                };
                create_wire_request_with_version(i as u8, version)
            })
            .collect();

        let addrs: Vec<SocketAddr> = (0..batch_size)
            .map(|i| format!("127.0.0.1:{}", 8080 + i).parse().unwrap())
            .collect();

        let total_bytes = request_pool.iter().map(|r| r.len()).sum::<usize>();

        bencher
            .counter(BytesCount::new(total_bytes))
            .bench_local(move || {
                for (request_bytes, addr) in request_pool.iter_mut().zip(addrs.iter()) {
                    handler.collect_request(request_bytes, *addr);
                }

                let mut byte_count = 0;
                handler.generate_responses(|_addr, bytes| {
                    byte_count += bytes.len();
                });

                black_box(byte_count)
            });
    }
}
