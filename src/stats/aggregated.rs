// Copyright 2017-2021 int08h LLC
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

use crate::stats::ClientStats;
use crate::stats::ServerStats;
use crate::Error;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::net::IpAddr;

///
/// Implementation of `ServerStats` that provides high-level aggregated client statistics. No
/// per-client statistic are maintained and runtime memory use is constant.
///
#[allow(dead_code)]
pub struct AggregatedStats {
    rfc_requests: u64,
    classic_requests: u64,
    invalid_requests: u64,
    health_checks: u64,
    rfc_responses_sent: u64,
    classic_responses_sent: u64,
    bytes_sent: usize,
    send_failed_attempts: u64,
    send_retry_attempts: u64,
    empty_map: HashMap<IpAddr, ClientStats>,
}

impl Default for AggregatedStats {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregatedStats {
    #[allow(dead_code)]
    pub fn new() -> Self {
        AggregatedStats {
            rfc_requests: 0,
            classic_requests: 0,
            invalid_requests: 0,
            health_checks: 0,
            rfc_responses_sent: 0,
            classic_responses_sent: 0,
            bytes_sent: 0,
            send_failed_attempts: 0,
            send_retry_attempts: 0,
            empty_map: HashMap::new(),
        }
    }
}

impl ServerStats for AggregatedStats {
    fn add_rfc_request(&mut self, _: &IpAddr) {
        self.rfc_requests += 1
    }

    fn add_classic_request(&mut self, _: &IpAddr) {
        self.classic_requests += 1
    }

    fn add_invalid_request(&mut self, _: &IpAddr, _: &Error) {
        self.invalid_requests += 1
    }

    fn add_failed_send_attempt(&mut self, _: &IpAddr) {
        self.send_failed_attempts += 1;
    }

    fn add_retried_send_attempt(&mut self, _: &IpAddr) {
        self.send_retry_attempts += 1;
    }

    fn add_health_check(&mut self, _: &IpAddr) {
        self.health_checks += 1
    }

    fn add_rfc_response(&mut self, _: &IpAddr, bytes_sent: usize) {
        self.bytes_sent += bytes_sent;
        self.rfc_responses_sent += 1;
    }

    fn add_classic_response(&mut self, _: &IpAddr, bytes_sent: usize) {
        self.bytes_sent += bytes_sent;
        self.classic_responses_sent += 1;
    }

    fn total_valid_requests(&self) -> u64 {
        self.rfc_requests + self.classic_requests
    }

    fn num_rfc_requests(&self) -> u64 {
        self.rfc_requests
    }

    fn num_classic_requests(&self) -> u64 {
        self.classic_requests
    }

    fn total_invalid_requests(&self) -> u64 {
        self.invalid_requests
    }

    fn total_health_checks(&self) -> u64 {
        self.health_checks
    }

    fn total_failed_send_attempts(&self) -> u64 {
        self.send_failed_attempts
    }

    fn total_retried_send_attempts(&self) -> u64 {
        self.send_retry_attempts
    }

    fn total_responses_sent(&self) -> u64 {
        self.rfc_responses_sent + self.classic_responses_sent
    }

    fn num_rfc_responses_sent(&self) -> u64 {
        self.rfc_responses_sent
    }

    fn num_classic_responses_sent(&self) -> u64 {
        self.classic_responses_sent
    }

    fn total_bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    fn total_unique_clients(&self) -> u64 {
        0
    }

    fn stats_for_client(&self, _addr: &IpAddr) -> Option<&ClientStats> {
        None
    }

    fn iter(&self) -> Iter<IpAddr, ClientStats> {
        self.empty_map.iter()
    }

    fn clear(&mut self) {
        self.rfc_requests = 0;
        self.classic_requests = 0;
        self.invalid_requests = 0;
        self.health_checks = 0;
        self.rfc_responses_sent = 0;
        self.classic_responses_sent = 0;
        self.bytes_sent = 0;
        self.send_failed_attempts = 0;
        self.send_retry_attempts = 0;
    }
}
