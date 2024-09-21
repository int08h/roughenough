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

//!
//! Facilities for tracking client requests to the server
//!

use std::collections::hash_map::Iter;
use std::net::IpAddr;
use crate::Error;
pub use crate::stats::aggregated::AggregatedStats;
pub use crate::stats::per_client::PerClientStats;

mod aggregated;
mod per_client;

///
/// Specific metrics tracked per each client
///
#[derive(Debug, Clone, Copy)]
pub struct ClientStatEntry {
    pub rfc_requests: u64,
    pub classic_requests: u64,
    pub invalid_requests: u64,
    pub health_checks: u64,
    pub rfc_responses_sent: u64,
    pub classic_responses_sent: u64,
    pub bytes_sent: usize,
    pub failed_send_attempts: u64,
    pub retried_send_attempts: u64,
}

impl ClientStatEntry {
    fn new() -> Self {
        ClientStatEntry {
            rfc_requests: 0,
            classic_requests: 0,
            invalid_requests: 0,
            health_checks: 0,
            rfc_responses_sent: 0,
            classic_responses_sent: 0,
            bytes_sent: 0,
            failed_send_attempts: 0,
            retried_send_attempts: 0,
        }
    }
}

///
/// Implementations of this trait record client activity
///
pub trait ServerStats {
    fn add_rfc_request(&mut self, addr: &IpAddr);

    fn add_classic_request(&mut self, addr: &IpAddr);

    fn add_invalid_request(&mut self, addr: &IpAddr, err: &Error);

    fn add_failed_send_attempt(&mut self, addr: &IpAddr);

    fn add_retried_send_attempt(&mut self, addr: &IpAddr);

    fn add_health_check(&mut self, addr: &IpAddr);

    fn add_rfc_response(&mut self, addr: &IpAddr, bytes_sent: usize);

    fn add_classic_response(&mut self, addr: &IpAddr, bytes_sent: usize);

    fn total_valid_requests(&self) -> u64;

    fn num_rfc_requests(&self) -> u64;

    fn num_classic_requests(&self) -> u64;

    fn total_invalid_requests(&self) -> u64;

    fn total_health_checks(&self) -> u64;

    fn total_failed_send_attempts(&self) -> u64;

    fn total_retried_send_attempts(&self) -> u64;

    fn total_responses_sent(&self) -> u64;

    fn num_rfc_responses_sent(&self) -> u64;

    fn num_classic_responses_sent(&self) -> u64;

    fn total_bytes_sent(&self) -> usize;

    fn total_unique_clients(&self) -> u64;

    fn stats_for_client(&self, addr: &IpAddr) -> Option<&ClientStatEntry>;

    fn iter(&self) -> Iter<IpAddr, ClientStatEntry>;

    fn clear(&mut self);
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};
    use crate::Error;
    use crate::stats::{PerClientStats, ServerStats};

    #[test]
    fn simple_stats_starts_empty() {
        let stats = PerClientStats::new();

        assert_eq!(stats.total_valid_requests(), 0);
        assert_eq!(stats.total_invalid_requests(), 0);
        assert_eq!(stats.total_health_checks(), 0);
        assert_eq!(stats.total_responses_sent(), 0);
        assert_eq!(stats.total_bytes_sent(), 0);
        assert_eq!(stats.total_unique_clients(), 0);
        assert_eq!(stats.total_failed_send_attempts(), 0);
        assert_eq!(stats.total_retried_send_attempts(), 0);
        assert_eq!(stats.num_overflows(), 0);
    }

    #[test]
    fn client_requests_are_tracked() {
        let mut stats = PerClientStats::new();

        let ip1 = "127.0.0.1".parse().unwrap();
        let ip2 = "127.0.0.2".parse().unwrap();
        let ip3 = "127.0.0.3".parse().unwrap();

        stats.add_classic_request(&ip1);
        stats.add_classic_request(&ip2);
        stats.add_classic_request(&ip3);
        stats.add_rfc_request(&ip3);
        assert_eq!(stats.total_valid_requests(), 4);
        assert_eq!(stats.num_classic_requests(), 3);
        assert_eq!(stats.num_rfc_requests(), 1);

        stats.add_invalid_request(&ip2, &Error::RequestTooLarge);
        assert_eq!(stats.total_invalid_requests(), 1);

        assert_eq!(stats.total_unique_clients(), 3);
    }

    #[test]
    fn per_client_stats() {
        let mut stats = PerClientStats::new();
        let ip = "127.0.0.3".parse().unwrap();

        stats.add_classic_request(&ip);
        stats.add_rfc_response(&ip, 2048);
        stats.add_classic_response(&ip, 1024);
        stats.add_classic_response(&ip, 1024);
        stats.add_failed_send_attempt(&ip);

        let entry = stats.stats_for_client(&ip).unwrap();
        assert_eq!(entry.classic_requests, 1);
        assert_eq!(entry.invalid_requests, 0);
        assert_eq!(entry.rfc_responses_sent, 1);
        assert_eq!(entry.classic_responses_sent, 2);
        assert_eq!(entry.bytes_sent, 4096);
        assert_eq!(entry.failed_send_attempts, 1);
        assert_eq!(entry.retried_send_attempts, 0);
    }

    #[test]
    fn overflow_max_entries() {
        let mut stats = PerClientStats::with_limit(100);

        for i in 0..201 {
            let ipv4 = Ipv4Addr::from(i as u32);
            let addr = IpAddr::from(ipv4);

            stats.add_classic_request(&addr);
        }

        assert_eq!(stats.total_unique_clients(), 100);
        assert_eq!(stats.num_overflows(), 101);
    }
}
