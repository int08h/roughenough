use divan::counter::BytesCount;
use divan::{AllocProfiler, Bencher, black_box_drop};
use protocol::cursor::ParseCursor;
use protocol::request::Request;
use protocol::response::Response;
use protocol::tags::Nonce;
use protocol::wire::{FromFrame, ToWire};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

mod request {
    use super::*;

    #[divan::bench(min_time = 0.250)]
    fn parse(bencher: Bencher) {
        let raw = &include_bytes!("../testdata/rfc-request.071039e5");

        bencher
            .counter(BytesCount::new(raw.len()))
            .with_inputs(|| raw.to_vec())
            .bench_local_refs(|data| {
                let mut cursor = ParseCursor::new(data);
                black_box_drop(Request::from_frame(&mut cursor).unwrap())
            })
    }

    #[allow(clippy::unit_arg)]
    #[divan::bench(min_time = 0.250)]
    fn create(bencher: Bencher) {
        let n = [42u8; 32];
        let nonce = Nonce::from(n);

        bencher
            .with_inputs(|| vec![0u8; 1024])
            .bench_local_refs(|buf| {
                let mut cursor = ParseCursor::new(buf);
                let r = divan::black_box(Request::new(&nonce));
                black_box_drop(r.to_wire(&mut cursor).unwrap())
            });
    }
}

mod response {
    use super::*;

    #[divan::bench(min_time = 0.250)]
    fn parse_path0(bencher: Bencher) {
        let raw = &include_bytes!("../testdata/rfc-response.071039e5");

        bencher
            .counter(BytesCount::new(raw.len()))
            .with_inputs(|| raw.to_vec())
            .bench_local_refs(|data| {
                let mut cursor = ParseCursor::new(data);
                black_box_drop(Response::from_frame(&mut cursor).unwrap())
            })
    }

    #[divan::bench(min_time = 0.250)]
    fn parse_path8(bencher: Bencher) {
        let raw = &include_bytes!("../testdata/rfc-response.path8.index2.4c16c619");

        bencher
            .counter(BytesCount::new(raw.len()))
            .with_inputs(|| raw.to_vec())
            .bench_local_refs(|data| {
                let mut cursor = ParseCursor::new(data);
                black_box_drop(Response::from_frame(&mut cursor).unwrap())
            })
    }
}
