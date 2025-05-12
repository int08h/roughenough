// Copyright 2017-2025 int08h LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//!
//! Quick (and dirty) estimates of client request entropy
//!

use crate::stats::popcount;
use crate::stats::popcount::PopcountFn;

/// At least this many bytes need to be seen before any estimates will be generated
const MIN_OBSERVATIONS_REQUIRED: u32 = 256;

#[derive(Debug)]
struct EntropyEstimator {
    byte_frequency: [u16; 256],
    observation_count: u32,
    num_ones_set: u32,
    popcount_fn: PopcountFn,
}

impl Default for EntropyEstimator {
    fn default() -> Self {
        Self {
            byte_frequency: [0; 256],
            observation_count: 0,
            num_ones_set: 0,
            popcount_fn: popcount::get_fastest_fn(),
        }
    }
}

impl EntropyEstimator {
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            let idx = b as usize;
            self.byte_frequency[idx] = self.byte_frequency[idx].saturating_add(1);
        }

        self.observation_count = self.observation_count.saturating_add(data.len() as u32);

        let popcount = (self.popcount_fn)(data);
        self.num_ones_set = self.num_ones_set.saturating_add(popcount);
    }

    pub fn reset(&mut self) {
        self.byte_frequency.fill(0);
        self.observation_count = 0;
    }

    pub fn observation_count(&self) -> u32 {
        self.observation_count
    }

    /// Estimates the Shannon entropy: the average minimum number of bits needed to encode
    /// a string of symbols.
    ///
    /// Will return `None` if fewer than `MIN_OBSERVATIONS_REQUIRED` bytes have been processed.
    pub fn shannon_entropy(&self) -> Option<f64> {
        if self.observation_count < MIN_OBSERVATIONS_REQUIRED {
            return None;
        }

        let mut entropy = 0.0;
        for &freq in &self.byte_frequency {
            let probability = freq as f64 / self.observation_count as f64;
            if probability > 0.0 {
                // entropy += probability * (1.0 / probability).log2();
                entropy -= probability * probability.log2();
            }
        }

        Some(entropy)
    }

    /// Returns sum of all byte frequencies divided by the number of observations.
    /// Truly random data should return ~127.5.
    ///
    /// Will return `None` if fewer than `MIN_OBSERVATIONS_REQUIRED` bytes have been processed.
    pub fn arithmetic_mean(&self) -> Option<f64> {
        if self.observation_count < MIN_OBSERVATIONS_REQUIRED {
            return None;
        }

        let mut sum = 0.0;
        for (i, &freq) in self.byte_frequency.iter().enumerate() {
            sum += (i as f64) * (freq as f64);
        }

        Some(sum / self.observation_count as f64)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_empty() {
        let estimator = EntropyEstimator::default();
        let empty_array = [0u16; 256];

        assert_eq!(estimator.observation_count(), 0);
        assert_eq!(estimator.byte_frequency, empty_array);

        println!("size_of<EntropyEstimator> = {}", std::mem::size_of::<EntropyEstimator>());
    }

    #[test]
    fn observation_count_matches_expectation() {
        let mut estimator = EntropyEstimator::default();

        estimator.update(b"hello world");
        assert_eq!(estimator.observation_count(), 11);

        estimator.update(b"sparkling combinatorics");
        assert_eq!(estimator.observation_count(), 34);
    }

    #[test]
    fn reset_clears_state() {
        let empty_array = [0u16; 256];
        let mut estimator = EntropyEstimator::default();

        estimator.update(b"apples and pears");
        assert_eq!(estimator.observation_count(), 16);
        assert_ne!(estimator.byte_frequency, empty_array);

        estimator.reset();
        assert_eq!(estimator.observation_count(), 0);
        assert_eq!(estimator.byte_frequency, empty_array);
    }

    #[test]
    fn bytes_are_counted_correctly() {
        let mut estimator = EntropyEstimator::default();

        estimator.update(b"hello world");

        let expected_frequencies = [
            (b'h', 1), (b'e', 1), (b'l', 3), (b'o', 2),
            (b' ', 1), (b'w', 1), (b'r', 1), (b'd', 1),
            (0xaa, 0),
        ];

        for (letter, count) in expected_frequencies {
            assert_eq!(
                estimator.byte_frequency[letter as usize], count,
                "expected frequency for {} to be {}", letter, count
            );
        }
    }

    #[test]
    fn estimates_are_only_computed_after_enough_data() {
        let mut estimator = EntropyEstimator::default();

        for _ in 0..MIN_OBSERVATIONS_REQUIRED - 1 {
            estimator.update(b"x");
        }
        assert_eq!(estimator.shannon_entropy(), None, "expected no estimate before enough data");
        assert_eq!(estimator.arithmetic_mean(), None, "expected no mean before enough data");

        estimator.update(b"x");
        assert!(estimator.shannon_entropy().is_some(), "expected an estimate");
        assert!(estimator.arithmetic_mean().is_some(), "expected a mean");
    }

    #[test]
    fn estimates_are_computed_correctly() {
        // Roman alphabet ~= 4.7 bits per symbol
        let alphabet = b"abcdefghijklmnopqrstuvwxyz".repeat(10);

        // Every value appears once = 8.0 bits per symbol
        let all_values = (0..256).map(|i| i as u8).collect::<Vec<_>>();

        // '1' repeating 256 times = 0.0 bits per symbol
        let just_ones = vec![1u8; 256];

        // (data, expected shannon entropy, expected arithmetic mean)
        let test_cases = [
            (&alphabet[..], 4.7, 109.5),
            (&all_values, 8.0, 127.5),
            (&just_ones, 0.0, 1.0),
        ];

        let mut estimator = EntropyEstimator::default();
        for (data, expected_entropy, expected_mean) in test_cases {
            estimator.reset();
            estimator.update(data);

            let calculated_entropy = estimator.shannon_entropy().unwrap();
            let entropy_delta = (calculated_entropy - expected_entropy).abs();

            let calculated_mean = estimator.arithmetic_mean().unwrap();
            let mean_delta = (calculated_mean - expected_mean).abs();

            assert!(entropy_delta < 0.01,
                "expected entropy to be {} but was {} in \n{:?}",
                expected_entropy, calculated_entropy, estimator
            );

            assert!(mean_delta < 0.01,
                "expected mean to be {} but was {} in \n{:?}",
                expected_mean, calculated_mean, estimator
            )
        }
    }
}
