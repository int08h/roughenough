// Copyright 2017-2024 int08h LLC
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
//! Coalesces client statistics from all workers and persists aggregated data.
//!

use crate::stats::{ClientStats, StatsQueue};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

static MAX_CLIENTS: usize = 256_000;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
struct Client {
    ip_addr: IpAddr,
    last_seen: Instant,
    first_seen: Instant,
}

// Implement Ord to make our priority queue a min-heap instead of default max-heap
impl Ord for Client {
    fn cmp(&self, other: &Self) -> Ordering {
        other.last_seen
            .cmp(&self.last_seen)
            .then_with(|| self.first_seen.cmp(&other.first_seen))
    }
}

impl PartialOrd for Client {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct Reporter {
    source_queue: Arc<StatsQueue>,
    client_stats: HashMap<IpAddr, ClientStats>,
    last_update: Instant,
    report_interval: Duration,
    output_location: PathBuf,
}

impl Reporter {

    pub fn new(source_queue: Arc<StatsQueue>, output_location: &Path, report_interval: &Duration) -> Result<Reporter, Error> {
        if !output_location.is_dir() {
            return Err(Error::new(ErrorKind::InvalidInput, "output location is not a directory"));
        }

        if output_location.metadata()?.permissions().readonly() {
            return Err(Error::new(ErrorKind::PermissionDenied, "output location is readonly"));
        }

        if report_interval.is_zero() || report_interval.as_secs() < 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "report interval invalid"));
        }

        Ok(Reporter {
            source_queue,
            client_stats: HashMap::with_capacity(MAX_CLIENTS),
            last_update: Instant::now(),
            report_interval: report_interval.clone(),
            output_location: output_location.to_path_buf(),
        })
    }

}