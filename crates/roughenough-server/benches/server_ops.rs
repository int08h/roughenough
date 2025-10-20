use std::net::SocketAddr;
use std::time::Duration;

use divan::counter::BytesCount;
use divan::{AllocProfiler, Bencher};
use roughenough_keys::seed::MemoryBackend;
use roughenough_protocol::ToFrame;
use roughenough_protocol::request::Request;
use roughenough_protocol::tags::{Nonce, Version};
use roughenough_protocol::util::ClockSource;
use roughenough_server::args::{Args, ProtocolVersionArg, SeedBackendArg};
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

fn create_request_handler() -> RequestHandler {
    let args = Args {
        batch_size: 64,
        interface: "0.0.0.0".to_string(),
        port: 2002,
        num_threads: 1,
        protocol: ProtocolVersionArg::V14,
        fixed_offset: 0,
        quiet: false,
        rotation_interval: 1,
        metrics_interval: 60,
        seed: "".to_string(),
        seed_backend: SeedBackendArg::Memory,
        verbose: 0,
        metrics_output: None,
    };

    let seed = Box::new(MemoryBackend::from_random());
    let ks = KeySource::new(
        Version::RfcDraft14,
        seed,
        ClockSource::System,
        Duration::from_secs(60),
    );
    let responder = ResponseHandler::new(args.batch_size, ks);

    RequestHandler::new(responder)
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
}
