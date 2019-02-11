// Copyright 2017-2019 int08h LLC
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
//! Adds deliberate errors to client responses.
//!

use rand::{FromEntropy, Rng};
use rand::rngs::SmallRng;
use rand::distributions::{Bernoulli, Distribution};
use rand::seq::SliceRandom;

use crate::RtMessage;
use crate::grease::Pathologies::*;

enum Pathologies {
    RandomlyOrderTags,
    CorruptResponseSignature,
    // TODO(stuart) semantic pathologies
}

static ALL_PATHOLOGIES: &[Pathologies] = &[
    RandomlyOrderTags,
    CorruptResponseSignature
];

pub struct Grease {
    enabled: bool,
    dist: Bernoulli,
    prng: SmallRng,
}

impl Grease {
    pub fn new(fault_percentage: u8) -> Self {
        Grease {
            enabled: fault_percentage > 0,
            dist: Bernoulli::from_ratio(u32::from(fault_percentage), 100),
            prng: SmallRng::from_entropy(),
        }
    }

    #[inline]
    pub fn should_add_error(&mut self) -> bool {
        if self.enabled { self.prng.sample(self.dist) } else { false }
    }

    pub fn add_errors(&mut self, src_msg: &RtMessage) -> RtMessage {
        match ALL_PATHOLOGIES.choose(&mut self.prng) {
            Some(CorruptResponseSignature) => src_msg.to_owned(),
            Some(RandomlyOrderTags) => src_msg.to_owned(),
            None => unreachable!()
        }
    }
}

#[cfg(test)]
mod test {
    use crate::grease::Grease;
    use crate::RtMessage;

    #[test]
    fn verify_error_probability() {
        const TRIALS: u64 = 100_000;
        const TOLERANCE: f64 = 0.75;

        for target in 1..50 {
            let mut g = Grease::new(target);
            let (lower, upper) = (target as f64 - TOLERANCE, target as f64 + TOLERANCE);

            let acc: u64 = (0..TRIALS)
                .map(|_| if g.should_add_error() { 1 } else { 0 })
                .sum();

            let percentage = 100.0 * (acc as f64 / TRIALS as f64);

            assert_eq!(
                percentage > lower && percentage < upper,
                true,
                "target {}, actual {} [{}, {}]", target, percentage, lower, upper
            );
        }
    }
}
