use std::hint::black_box;
use std::sync::LazyLock;
use std::time::Instant;

/// Function pointer to a `popcount` implementation
pub type PopcountFn = fn(&[u8]) -> u32;

/// Returns the fastest implementation of `popcount` selected by a runtime benchmark.
pub fn get_fastest_fn() -> PopcountFn {
    static FASTEST_POPCOUNT_FN: LazyLock<PopcountFn> = LazyLock::new(|| choose_popcount());

    *FASTEST_POPCOUNT_FN
}

// Crude benchmark to select the fastest popcount implementation for the platform
// this code is executing on.
fn choose_popcount() -> PopcountFn {
    const ITERATIONS: usize = 10_0000;
    let data = Vec::from([0x22u8; 32]);

    let start_u64 = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(calc_popcount_u64(black_box(&data)));
    }
    let duration_u64 = start_u64.elapsed();

    let start_u128 = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(calc_popcount_u128(black_box(&data)));
    }
    let duration_u128 = start_u128.elapsed();

    println!("u64  {:>5.1} ms  {:.1} MiB/sec",
         duration_u64.as_millis() as f64,
         (ITERATIONS as f64 * 32.0) / duration_u64.as_secs_f64() / 1024.0 / 1024.0
    );
    println!("u128 {:>5.1} ms  {:.1} MiB/sec",
         duration_u128.as_millis() as f64,
         (ITERATIONS as f64 * 32.0) / duration_u128.as_secs_f64() / 1024.0 / 1024.0
    );

    if duration_u128 < duration_u64 {
        calc_popcount_u128
    } else {
        calc_popcount_u64
    }
}

#[inline]
fn calc_popcount_u64(data: &[u8]) -> u32 {
    const U64_SIZE: usize = std::mem::size_of::<u64>();

    debug_assert!(
        data.len() % U64_SIZE == 0,
        "data length must be a multiple of 8 bytes, got {} bytes",
        data.len()
    );

    data.chunks_exact(U64_SIZE)
        .map(|chunk| {
            let array = <[u8; U64_SIZE]>::try_from(chunk).unwrap();
            u64::from_ne_bytes(array).count_ones()
        })
        .sum()
}

#[inline]
fn calc_popcount_u128(data: &[u8]) -> u32 {
    const U128_SIZE: usize = std::mem::size_of::<u128>();

    debug_assert!(
        data.len() % U128_SIZE == 0,
        "data length must be a multiple of 16 bytes, got {} bytes",
        data.len()
    );

    data.chunks_exact(U128_SIZE)
        .map(|chunk| {
            let array = <[u8; U128_SIZE]>::try_from(chunk).unwrap();
            u128::from_ne_bytes(array).count_ones()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::{calc_popcount_u64, calc_popcount_u128, get_fastest_fn};

    #[test]
    fn get_fastest_fn_returns() {
        get_fastest_fn();
    }

    #[test]
    fn test_calc_popcount_u64_empty() {
        let data: Vec<u8> = vec![];
        assert_eq!(calc_popcount_u64(&data), 0);
    }

    #[test]
    fn test_calc_popcount_u64_basic() {
        let data: Vec<u8> = vec![
            0b10101010, 0b11110000, 0b00001111, 0b11111111, // 4 + 4 + 4 + 8
            0b00000000, 0b00000000, 0b00000000, 0b00000000, // 0
        ];
        assert_eq!(calc_popcount_u64(&data), 4 + 4 + 4 + 8);
    }
}
