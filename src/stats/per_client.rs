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

use crate::stats::{ClientStats, MAX_CLIENTS};
use crate::stats::ServerStats;
use crate::Error;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::net::IpAddr;

///
/// Implementation of `ServerStats` that provides granular per-client request/response counts.
///
/// Each unique client address is used to key a hashmap. A maximum of `MAX_CLIENTS` entries
/// are kept in the map to bound memory use. Excess entries beyond `MAX_CLIENTS` are ignored
/// and `num_overflows` is incremented.
///
pub struct PerClientStats {
    clients: HashMap<IpAddr, ClientStats>,
    num_overflows: u64,
    max_clients: usize,
}

impl Default for PerClientStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PerClientStats {
    pub fn new() -> Self {
        PerClientStats {
            clients: HashMap::with_capacity(MAX_CLIENTS),
            num_overflows: 0,
            max_clients: MAX_CLIENTS,
        }
    }

    // visible for testing
    #[cfg(test)]
    pub fn with_limit(limit: usize) -> Self {
        PerClientStats {
            clients: HashMap::with_capacity(limit),
            num_overflows: 0,
            max_clients: limit,
        }
    }

    #[inline]
    fn too_many_entries(&mut self) -> bool {
        let too_big = self.clients.len() >= self.max_clients;

        if too_big {
            self.num_overflows += 1;
        }

        too_big
    }

    #[allow(dead_code)]
    pub fn num_overflows(&self) -> u64 {
        self.num_overflows
    }
}

impl ServerStats for PerClientStats {
    fn add_rfc_request(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with_key(|addr| ClientStats::new(addr.clone()))
            .rfc_requests += 1;
    }

    fn add_classic_request(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with_key(|addr| ClientStats::new(addr.clone()))
            .classic_requests += 1;
    }

    fn add_invalid_request(&mut self, addr: &IpAddr, _: &Error) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with_key(|addr| ClientStats::new(addr.clone()))
            .invalid_requests += 1;
    }

    fn add_failed_send_attempt(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with_key(|addr| ClientStats::new(addr.clone()))
            .failed_send_attempts += 1;
    }

    fn add_retried_send_attempt(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with_key(|addr| ClientStats::new(addr.clone()))
            .retried_send_attempts += 1;
    }

    fn add_health_check(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with_key(|addr| ClientStats::new(addr.clone()))
            .health_checks += 1;
    }

    fn add_rfc_response(&mut self, addr: &IpAddr, bytes_sent: usize) {
        if self.too_many_entries() {
            return;
        }
        let entry = self
            .clients
            .entry(*addr)
            .or_insert_with_key(|addr| ClientStats::new(addr.clone()));

        entry.rfc_responses_sent += 1;
        entry.bytes_sent += bytes_sent;
    }

    fn add_classic_response(&mut self, addr: &IpAddr, bytes_sent: usize) {
        if self.too_many_entries() {
            return;
        }
        let entry = self
            .clients
            .entry(*addr)
            .or_insert_with_key(|addr| ClientStats::new(addr.clone()));

        entry.classic_responses_sent += 1;
        entry.bytes_sent += bytes_sent;
    }

    fn total_valid_requests(&self) -> u64 {
        self.clients.values()
            .map(|&v| v.rfc_requests as u64 + v.classic_requests as u64)
            .sum()
    }

    fn num_rfc_requests(&self) -> u64 {
        self.clients.values()
            .map(|&v| v.rfc_requests as u64)
            .sum()
    }

    fn num_classic_requests(&self) -> u64 {
        self.clients.values()
            .map(|&v| v.classic_requests as u64)
            .sum()
    }

    fn total_invalid_requests(&self) -> u64 {
        self.clients.values()
            .map(|&v| v.invalid_requests as u64)
            .sum()
    }

    fn total_health_checks(&self) -> u64 {
        self.clients.values()
            .map(|&v| v.health_checks as u64)
            .sum()
    }

    fn total_failed_send_attempts(&self) -> u64 {
        self.clients.values()
            .map(|&v| v.failed_send_attempts as u64)
            .sum()
    }

    fn total_retried_send_attempts(&self) -> u64 {
        self.clients.values()
            .map(|&v| v.retried_send_attempts as u64)
            .sum()
    }

    fn total_responses_sent(&self) -> u64 {
        self.clients
            .values()
            .map(|&v| v.rfc_responses_sent + v.classic_responses_sent)
            .map(|v| v as u64)
            .sum()
    }

    fn num_rfc_responses_sent(&self) -> u64 {
        self.clients.values()
            .map(|&v| v.rfc_responses_sent as u64)
            .sum()
    }

    fn num_classic_responses_sent(&self) -> u64 {
        self.clients
            .values()
            .map(|&v| v.classic_responses_sent)
            .map(|v| v as u64)
            .sum()
    }

    fn total_bytes_sent(&self) -> usize {
        self.clients.values()
            .map(|&v| v.bytes_sent)
            .sum()
    }

    fn total_unique_clients(&self) -> u64 {
        self.clients.len() as u64
    }

    fn stats_for_client(&self, addr: &IpAddr) -> Option<&ClientStats> {
        self.clients.get(addr)
    }

    fn iter(&self) -> Iter<IpAddr, ClientStats> {
        self.clients.iter()
    }

    fn clear(&mut self) {
        self.clients.clear();
        self.num_overflows = 0;
    }
}
