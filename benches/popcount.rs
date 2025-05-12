use std::fmt::{Display, Formatter};
use data_encoding::{BASE64, HEXLOWER};
use core::hint::black_box;

fn main() {
    divan::main();
}

struct BenchArg(Vec<u8>);

impl Display for BenchArg {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:4}...", HEXLOWER.encode(&self.0[0..4]))
    }
}

// Hamming distance from https://github.com/brandondong/hamming-bitwise-fast
pub fn hamming_bitwise_u64(x: &[u8], y: &[u8]) -> u32 {
    debug_assert_eq!(x.len(), y.len());
    debug_assert_eq!(x.len() % 8, 0);

    // Process 8 bytes at a time using u64
    let distance = x
        .chunks_exact(8)
        .zip(y.chunks_exact(8))
        .map(|(x_chunk, y_chunk)| {
            // This is safe because we know the chunks are exactly 8 bytes.
            // Also, we don't care whether the platform uses little-endian or big-endian
            // byte order. Since we're only XORing values, we just care that the
            // endianness is the same for both.
            let x_val = u64::from_ne_bytes(x_chunk.try_into().unwrap());
            let y_val = u64::from_ne_bytes(y_chunk.try_into().unwrap());
            (x_val ^ y_val).count_ones()
        })
        .sum::<u32>();

    distance
}

pub fn hamming_bitwise_u32(x: &[u8], y: &[u8]) -> u32 {
    debug_assert_eq!(x.len(), y.len());
    debug_assert_eq!(x.len() % 4, 0);

    // Process 4 bytes at a time using u32
    let distance = x
        .chunks_exact(4)
        .zip(y.chunks_exact(4))
        .map(|(x_chunk, y_chunk)| {
            let x_val = u32::from_ne_bytes(x_chunk.try_into().unwrap());
            let y_val = u32::from_ne_bytes(y_chunk.try_into().unwrap());
            (x_val ^ y_val).count_ones()
        })
        .sum::<u32>();

    distance
}

pub fn hamming_bitwise_u128(x: &[u8], y: &[u8]) -> u32 {
    debug_assert_eq!(x.len(), y.len());
    debug_assert_eq!(x.len() % 16, 0);

    // Process 16 bytes at a time using u128
    let distance = x
        .chunks_exact(16)
        .zip(y.chunks_exact(16))
        .map(|(x_chunk, y_chunk)| {
            let x_val = u128::from_ne_bytes(x_chunk.try_into().unwrap());
            let y_val = u128::from_ne_bytes(y_chunk.try_into().unwrap());
            (x_val ^ y_val).count_ones()
        })
        .sum::<u32>();

    distance
}

fn make_popcount_args() -> Vec<BenchArg> {
    let all_zeros: Vec<u8> = vec![0; 32];
    let all_ones: Vec<u8> = vec![255; 32];
    let random_1: Vec<u8> = BASE64.decode(b"oLSHBTHoq50eAivW97Ip6kOpdEeOzf4oBByIYGXxuRE=").unwrap();
    let random_2: Vec<u8> = BASE64.decode(b"Hrorl2XesFCcLXaIb4SbCmck80LAT9qLAPjPTgw99ZA=").unwrap();

    vec![
        BenchArg(all_zeros),
        BenchArg(all_ones),
        BenchArg(random_1),
        BenchArg(random_2),
    ]
}

fn make_hamming_args() -> Vec<BenchArg> {
    let random_1: Vec<u8> = BASE64.decode(b"oLSHBTHoq50eAivW97Ip6kOpdEeOzf4oBByIYGXxuRE=").unwrap();
    let random_2: Vec<u8> = BASE64.decode(b"Hrorl2XesFCcLXaIb4SbCmck80LAT9qLAPjPTgw99ZA=").unwrap();

    vec![
        BenchArg(random_1), 
        BenchArg(random_2)
    ]
}

#[divan::bench_group]
mod hamming {
    use super::*;

    #[divan::bench]
    fn int_u32(bencher: divan::Bencher) {
        let x = &make_hamming_args()[0];
        let y = &make_hamming_args()[1];
        bencher.bench_local(|| {
            black_box(hamming_bitwise_u32(&x.0, &y.0));
        });
    }

    #[divan::bench]
    fn int_u64(bencher: divan::Bencher) {
        let x = &make_hamming_args()[0];
        let y = &make_hamming_args()[1];
        bencher.bench_local(|| {
            black_box(hamming_bitwise_u64(&x.0, &y.0));
        });
    }

    #[divan::bench]
    fn int_u128(bencher: divan::Bencher) {
        let x = &make_hamming_args()[0];
        let y = &make_hamming_args()[1];
        bencher.bench_local(|| {
            black_box(hamming_bitwise_u128(&x.0, &y.0));
        });
    }
}

#[divan::bench_group]
mod popcount {
    use super::*;

    #[divan::bench(args = make_popcount_args())]
    fn int_u32(bencher: divan::Bencher, arg: &BenchArg) {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        bencher.bench_local(|| {
            black_box(
                arg.0.chunks_exact(U32_SIZE)
                    .map(|chunk| {
                        let array = <[u8; U32_SIZE]>::try_from(chunk).unwrap();
                        u32::from_ne_bytes(array).count_ones()
                    })
                    .sum::<u32>()
            );
        });
    }

    #[divan::bench(args = make_popcount_args())]
    fn int_u64(bencher: divan::Bencher, arg: &BenchArg) {
        const U64_SIZE: usize = std::mem::size_of::<u64>();
        bencher.bench_local(|| {
            black_box(
                arg.0.chunks_exact(U64_SIZE)
                    .map(|chunk| {
                        let array = <[u8; U64_SIZE]>::try_from(chunk).unwrap();
                        u64::from_ne_bytes(array).count_ones()
                    })
                    .sum::<u32>()
            );
        });
    }

    #[divan::bench(args = make_popcount_args())]
    fn int_u128(bencher: divan::Bencher, arg: &BenchArg) {
        const U128_SIZE: usize = std::mem::size_of::<u128>();
        bencher.bench_local(|| {
            black_box(
                arg.0.chunks_exact(U128_SIZE)
                    .map(|chunk| {
                        let array = <[u8; U128_SIZE]>::try_from(chunk).unwrap();
                        u128::from_ne_bytes(array).count_ones()
                    })
                    .sum::<u32>()
            );
        });
    }

    #[divan::bench(args = make_popcount_args())]
    fn baseline(bencher: divan::Bencher, arg: &BenchArg) {
        bencher.bench_local(|| {
            let data = arg.0.as_slice();
            black_box(data.iter().fold(0, |acc, &b| acc + b.count_ones()))
        })
    }
}