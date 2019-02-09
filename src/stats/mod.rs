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
//! Facilities for tracking client requests to the server
//!

use hashbrown::HashMap;
use hashbrown::hash_map::Iter;

use std::net::IpAddr;

///
/// Implementations of this trait record client activity
///
pub trait ServerStats {
    fn add_valid_request(&mut self, addr: &IpAddr);

    fn add_invalid_request(&mut self, addr: &IpAddr);

    fn add_health_check(&mut self, addr: &IpAddr);

    fn add_response(&mut self, addr: &IpAddr, bytes_sent: usize);

    fn total_valid_requests(&self) -> u64;

    fn total_invalid_requests(&self) -> u64;

    fn total_health_checks(&self) -> u64;

    fn total_responses_sent(&self) -> u64;

    fn total_bytes_sent(&self) -> usize;

    fn total_unique_clients(&self) -> u64;

    fn get_client_stats(&self, addr: &IpAddr) -> Option<&ClientStatEntry>;

    fn iter(&self) -> Iter<IpAddr, ClientStatEntry>;

    fn clear(&mut self);
}

///
/// Specific metrics tracked per each client
///
#[derive(Debug, Clone, Copy)]
pub struct ClientStatEntry {
    pub valid_requests: u64,
    pub invalid_requests: u64,
    pub health_checks: u64,
    pub responses_sent: u64,
    pub bytes_sent: usize,
}

impl ClientStatEntry {
    fn new() -> Self {
        ClientStatEntry {
            valid_requests: 0,
            invalid_requests: 0,
            health_checks: 0,
            responses_sent: 0,
            bytes_sent: 0,
        }
    }
}

///
/// Implementation of `ServerStats` that provides granular per-client request/response counts.
///
/// Maintains a maximum of `MAX_CLIENTS` unique entries to bound memory use. Excess
/// entries beyond `MAX_CLIENTS` are ignored and `num_overflows` is incremented.
///
pub struct PerClientStats {
    clients: HashMap<IpAddr, ClientStatEntry>,
    num_overflows: u64,
    max_clients: usize,
}

impl PerClientStats {

    /// Maximum number of stats entries to maintain to prevent
    /// unbounded memory growth.
    pub const MAX_CLIENTS: usize = 1_000_000;

    pub fn new() -> Self {
        PerClientStats {
            clients: HashMap::with_capacity(128),
            num_overflows: 0,
            max_clients: PerClientStats::MAX_CLIENTS,
        }
    }

    // visible for testing
    #[cfg(test)]
    fn with_limit(limit: usize) -> Self {
        PerClientStats {
            clients: HashMap::with_capacity(128),
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

        return too_big;
    }

    #[allow(dead_code)]
    pub fn num_overflows(&self) -> u64 {
        self.num_overflows
    }
}

impl ServerStats for PerClientStats {
    fn add_valid_request(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with(ClientStatEntry::new)
            .valid_requests += 1;
    }

    fn add_invalid_request(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with(ClientStatEntry::new)
            .invalid_requests += 1;
    }

    fn add_health_check(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with(ClientStatEntry::new)
            .health_checks += 1;
    }

    fn add_response(&mut self, addr: &IpAddr, bytes_sent: usize) {
        if self.too_many_entries() {
            return;
        }
        let entry = self.clients
            .entry(*addr)
            .or_insert_with(ClientStatEntry::new);

        entry.responses_sent += 1;
        entry.bytes_sent += bytes_sent;
    }

    fn total_valid_requests(&self) -> u64 {
        self.clients
            .values()
            .map(|&v| v.valid_requests)
            .sum()
    }

    fn total_invalid_requests(&self) -> u64 {
        self.clients
            .values()
            .map(|&v| v.invalid_requests)
            .sum()
    }

    fn total_health_checks(&self) -> u64 {
        self.clients
            .values()
            .map(|&v| v.health_checks)
            .sum()
    }

    fn total_responses_sent(&self) -> u64 {
        self.clients
            .values()
            .map(|&v| v.responses_sent)
            .sum()
    }

    fn total_bytes_sent(&self) -> usize {
        self.clients
            .values()
            .map(|&v| v.bytes_sent)
            .sum()
    }

    fn total_unique_clients(&self) -> u64 {
        self.clients.len() as u64
    }

    fn get_client_stats(&self, addr: &IpAddr) -> Option<&ClientStatEntry> {
        self.clients.get(addr)
    }

    fn iter(&self) -> Iter<IpAddr, ClientStatEntry> {
        self.clients.iter()
    }

    fn clear(&mut self) {
        self.clients.clear();
        self.num_overflows = 0;
    }
}

///
/// Implementation of `ServerStats` that provides high-level aggregated server statistics.
///
#[allow(dead_code)]
pub struct AggregatedStats {
    valid_requests: u64,
    invalid_requests: u64,
    health_checks: u64,
    responses_sent: u64,
    bytes_sent: usize,
    empty_map: HashMap<IpAddr, ClientStatEntry>,
}

impl AggregatedStats {

    #[allow(dead_code)]
    pub fn new() -> Self {
        AggregatedStats {
            valid_requests: 0,
            invalid_requests: 0,
            health_checks: 0,
            responses_sent: 0,
            bytes_sent: 0,
            empty_map: HashMap::new()
        }
    }
}

impl ServerStats for AggregatedStats {
    fn add_valid_request(&mut self, _: &IpAddr) {
        self.valid_requests += 1
    }

    fn add_invalid_request(&mut self, _: &IpAddr) {
        self.invalid_requests += 1
    }

    fn add_health_check(&mut self, _: &IpAddr) {
        self.health_checks += 1
    }

    fn add_response(&mut self, _: &IpAddr, bytes_sent: usize) {
        self.bytes_sent += bytes_sent;
        self.responses_sent += 1;
    }

    fn total_valid_requests(&self) -> u64 {
        self.valid_requests
    }

    fn total_invalid_requests(&self) -> u64 {
        self.invalid_requests
    }

    fn total_health_checks(&self) -> u64 {
        self.health_checks
    }

    fn total_responses_sent(&self) -> u64 {
        self.responses_sent
    }

    fn total_bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    fn total_unique_clients(&self) -> u64 {
        0
    }

    fn get_client_stats(&self, _addr: &IpAddr) -> Option<&ClientStatEntry> {
        None
    }

    fn iter(&self) -> Iter<IpAddr, ClientStatEntry> {
        self.empty_map.iter()
    }

    fn clear(&mut self) {}
}

#[cfg(test)]
mod test {
    use crate::stats::{ServerStats, PerClientStats};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn simple_stats_starts_empty() {
        let stats = PerClientStats::new();

        assert_eq!(stats.total_valid_requests(), 0);
        assert_eq!(stats.total_invalid_requests(), 0);
        assert_eq!(stats.total_health_checks(), 0);
        assert_eq!(stats.total_responses_sent(), 0);
        assert_eq!(stats.total_bytes_sent(), 0);
        assert_eq!(stats.total_unique_clients(), 0);
        assert_eq!(stats.num_overflows(), 0);
    }

    #[test]
    fn client_requests_are_tracked() {
        let mut stats = PerClientStats::new();

        let ip1 = "127.0.0.1".parse().unwrap();
        let ip2 = "127.0.0.2".parse().unwrap();
        let ip3 = "127.0.0.3".parse().unwrap();

        stats.add_valid_request(&ip1);
        stats.add_valid_request(&ip2);
        stats.add_valid_request(&ip3);
        assert_eq!(stats.total_valid_requests(), 3);

        stats.add_invalid_request(&ip2);
        assert_eq!(stats.total_invalid_requests(), 1);

        stats.add_response(&ip2, 8192);
        assert_eq!(stats.total_bytes_sent(), 8192);

        assert_eq!(stats.total_unique_clients(), 3);
    }

    #[test]
    fn per_client_stats() {
        let mut stats = PerClientStats::new();
        let ip = "127.0.0.3".parse().unwrap();

        stats.add_valid_request(&ip);
        stats.add_response(&ip, 2048);
        stats.add_response(&ip, 1024);

        let entry = stats.get_stats(&ip).unwrap();
        assert_eq!(entry.valid_requests, 1);
        assert_eq!(entry.invalid_requests, 0);
        assert_eq!(entry.responses_sent, 2);
        assert_eq!(entry.bytes_sent, 3072);
    }

    #[test]
    fn overflow_max_entries() {
        let mut stats = PerClientStats::with_limit(100);

        for i in 0..201 {
            let ipv4 = Ipv4Addr::from(i as u32);
            let addr = IpAddr::from(ipv4);

            stats.add_valid_request(&addr);
        };

        assert_eq!(stats.total_unique_clients(), 100);
        assert_eq!(stats.num_overflows(), 101);
    }
}


