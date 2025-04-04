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

use crate::stats::{ClientStats, StatsQueue, MAX_CLIENTS};
use ahash::AHashMap;
use chrono::Utc;
use csv;
use std::fs::File;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct Reporter {
    source_queue: Arc<StatsQueue>,
    client_stats: AHashMap<IpAddr, ClientStats>,
    next_update: Instant,
    report_interval: Duration,
    output_location: Option<PathBuf>,
}

impl Reporter {
    pub fn new(
        source_queue: Arc<StatsQueue>,
        report_interval: &Duration,
        output_location: Option<PathBuf>,
    ) -> Reporter {
        Reporter {
            source_queue,
            client_stats: AHashMap::with_capacity(MAX_CLIENTS),
            next_update: Instant::now() + *report_interval,
            report_interval: *report_interval,
            output_location,
        }
    }

    pub fn processing_loop(&mut self, keep_running: &AtomicBool) {
        while keep_running.load(Ordering::Relaxed) {
            self.receive_client_stats();

            if Instant::now() >= self.next_update {
                self.next_update = Instant::now() + self.report_interval;
                self.report();
                self.client_stats.clear();
            }

            sleep(Duration::from_secs(1));
        }
    }

    pub fn receive_client_stats(&mut self) {
        let start = Instant::now();
        let mut num_processed = 0;

        while let Some(stats) = self.source_queue.pop() {
            for client in stats {
                self.client_stats
                    .entry(client.ip_addr)
                    .or_insert_with_key(|ip_addr| ClientStats::new(*ip_addr))
                    .merge(&client);

                num_processed += 1;
            }
        }

        if num_processed > 0 {
            let elapsed = Instant::now().duration_since(start);
            info!(
                "Received {} client stat entries in {:.3} seconds",
                num_processed,
                elapsed.as_secs_f32()
            );
        }
    }

    pub fn report(&mut self) {
        let start = Instant::now();

        if self.client_stats.is_empty() {
            info!("No client stats to persist");
            return;
        }

        if self.output_location.is_none() {
            info!("No output location to persist to");
            return;
        }

        let filename = Utc::now()
            .format("roughenough-stats-%Y%m%d-%H%M%S.csv.zst")
            .to_string();

        let mut outpath = self.output_location.clone().unwrap();
        outpath.push(filename);

        info!(
            "Writing {} client statistics to: {}",
            self.client_stats.len(),
            outpath.display()
        );

        let outfile = match File::create(&outpath) {
            Ok(file) => file,
            Err(e) => {
                warn!("failed to open output file: {}", e);
                return;
            }
        };

        let zstd_writer = zstd::Encoder::new(outfile, 9)
            .unwrap()
            .auto_finish();

        let mut csv_writer = csv::WriterBuilder::new()
            .has_headers(true)
            .from_writer(zstd_writer);

        let mut num_processed = 0;
        for stat in self.client_stats.values() {
            match csv_writer.serialize(stat) {
                Ok(_) => num_processed += 1,
                Err(e) => {
                    warn!("serializing record failed: {}", e);
                    break;
                }
            }
        }

        info!(
            "Wrote {} records in {:.3} seconds",
            num_processed,
            start.elapsed().as_secs_f32()
        );
    }
}
