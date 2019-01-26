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
pub trait ClientStats {
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

    fn get_stats(&self, addr: &IpAddr) -> Option<&StatEntry>;

    fn iter(&self) -> Iter<IpAddr, StatEntry>;

    fn clear(&mut self);
}

///
/// Specific metrics tracked per each client
///
#[derive(Debug, Clone, Copy)]
pub struct StatEntry {
    pub valid_requests: u64,
    pub invalid_requests: u64,
    pub health_checks: u64,
    pub responses_sent: u64,
    pub bytes_sent: usize,
}

impl StatEntry {
    fn new() -> Self {
        StatEntry {
            valid_requests: 0,
            invalid_requests: 0,
            health_checks: 0,
            responses_sent: 0,
            bytes_sent: 0,
        }
    }
}

///
/// Implementation of `ClientStats` backed by a hashmap.
///
/// Maintains a maximum of `MAX_CLIENTS` unique entries to bound memory use. Excess
/// entries beyond `MAX_CLIENTS` are ignored and `num_overflows` is incremented.
///
pub struct SimpleStats {
    clients: HashMap<IpAddr, StatEntry>,
    num_overflows: u64,
    max_clients: usize,
}

impl SimpleStats {

    /// Maximum number of stats entries to maintain to prevent
    /// unbounded memory growth.
    pub const MAX_CLIENTS: usize = 1_000_000;

    pub fn new() -> Self {
        SimpleStats {
            clients: HashMap::with_capacity(128),
            num_overflows: 0,
            max_clients: SimpleStats::MAX_CLIENTS,
        }
    }

    // visible for testing
    #[cfg(test)]
    fn with_limits(limit: usize) -> Self {
        SimpleStats {
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

impl ClientStats for SimpleStats {
    fn add_valid_request(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with(StatEntry::new)
            .valid_requests += 1;
    }

    fn add_invalid_request(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with(StatEntry::new)
            .invalid_requests += 1;
    }

    fn add_health_check(&mut self, addr: &IpAddr) {
        if self.too_many_entries() {
            return;
        }
        self.clients
            .entry(*addr)
            .or_insert_with(StatEntry::new)
            .health_checks += 1;
    }

    fn add_response(&mut self, addr: &IpAddr, bytes_sent: usize) {
        if self.too_many_entries() {
            return;
        }
        let entry = self.clients
            .entry(*addr)
            .or_insert_with(StatEntry::new);

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

    fn get_stats(&self, addr: &IpAddr) -> Option<&StatEntry> {
        self.clients.get(addr)
    }

    fn iter(&self) -> Iter<IpAddr, StatEntry> {
        self.clients.iter()
    }

    fn clear(&mut self) {
        self.clients.clear();
        self.num_overflows = 0;
    }
}

///
/// A no-op implementation that does not track anything and has no runtime cost
///
#[allow(dead_code)]
pub struct NoOpStats {
    empty_map: HashMap<IpAddr, StatEntry>
}

impl NoOpStats {

    #[allow(dead_code)]
    pub fn new() -> Self {
        NoOpStats {
            empty_map: HashMap::new()
        }
    }
}

impl ClientStats for NoOpStats {
    fn add_valid_request(&mut self, _addr: &IpAddr) {}

    fn add_invalid_request(&mut self, _addr: &IpAddr) {}

    fn add_health_check(&mut self, _addr: &IpAddr) {}

    fn add_response(&mut self, _addr: &IpAddr, _bytes_sent: usize) {}

    fn total_valid_requests(&self) -> u64 {
        0
    }

    fn total_invalid_requests(&self) -> u64 {
        0
    }

    fn total_health_checks(&self) -> u64 {
        0
    }

    fn total_responses_sent(&self) -> u64 {
        0
    }

    fn total_bytes_sent(&self) -> usize {
        0
    }

    fn total_unique_clients(&self) -> u64 {
        0
    }

    fn get_stats(&self, _addr: &IpAddr) -> Option<&StatEntry> {
        None
    }

    fn iter(&self) -> Iter<IpAddr, StatEntry> {
        self.empty_map.iter()
    }

    fn clear(&mut self) {}
}

#[cfg(test)]
mod test {
    use crate::stats::{ClientStats, SimpleStats};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn simple_stats_starts_empty() {
        let stats = SimpleStats::new();

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
        let mut stats = SimpleStats::new();

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
        let mut stats = SimpleStats::new();
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
        let mut stats = SimpleStats::with_limits(100);

        for i in 0..201 {
            let ipv4 = Ipv4Addr::from(i as u32);
            let addr = IpAddr::from(ipv4);

            stats.add_valid_request(&addr);
        };

        assert_eq!(stats.total_unique_clients(), 100);
        assert_eq!(stats.num_overflows(), 101);
    }
}


