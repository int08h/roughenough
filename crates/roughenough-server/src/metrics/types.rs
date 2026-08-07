//! Metrics tracking structures for the Roughtime server

use std::ops::AddAssign;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub num_recv_wouldblock: usize,
    pub num_successful_sends: usize,
    pub num_failed_sends: usize,
    pub num_failed_polls: usize,
    pub num_failed_recvs: usize,
    /// Datagrams larger than `MAX_REQUEST_SIZE` dropped without a response:
    /// a truncated read would be Merkle-hashed as a leaf differing from the
    /// packet the client actually sent (RFC 5.3)
    pub num_oversized_dropped: usize,
}

impl AddAssign for NetworkMetrics {
    fn add_assign(&mut self, rhs: Self) {
        self.num_recv_wouldblock += rhs.num_recv_wouldblock;
        self.num_successful_sends += rhs.num_successful_sends;
        self.num_failed_sends += rhs.num_failed_sends;
        self.num_failed_polls += rhs.num_failed_polls;
        self.num_failed_recvs += rhs.num_failed_recvs;
        self.num_oversized_dropped += rhs.num_oversized_dropped;
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct RequestMetrics {
    pub num_ok_requests: usize,
    pub num_bad_requests: usize,
    pub num_runt_requests: usize,
    pub num_oversized_requests: usize,
    /// Requests whose SRV tag did not match this server's long-term key
    /// (RFC 5.2: such requests are ignored)
    pub num_srv_mismatch: usize,
    /// Requests whose VER list shares no version with this server
    /// (RFC 5.1.1: such requests may be ignored)
    pub num_no_common_version: usize,
    /// Requests dropped because their negotiated version would exceed the
    /// per-batch distinct version limit (each distinct version costs one
    /// signature; see `ResponseHandler::MAX_VERSIONS_PER_BATCH`)
    pub num_version_overflow: usize,
}

impl AddAssign for RequestMetrics {
    fn add_assign(&mut self, rhs: Self) {
        self.num_ok_requests += rhs.num_ok_requests;
        self.num_bad_requests += rhs.num_bad_requests;
        self.num_runt_requests += rhs.num_runt_requests;
        self.num_oversized_requests += rhs.num_oversized_requests;
        self.num_srv_mismatch += rhs.num_srv_mismatch;
        self.num_no_common_version += rhs.num_no_common_version;
        self.num_version_overflow += rhs.num_version_overflow;
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResponseMetrics {
    pub num_responses: usize,
    pub num_bytes_sent: usize,
    /// Fixed array (not a Vec) so the struct is `Copy` and a metrics publish
    /// allocates nothing; serde's derive only covers arrays up to 32 elements,
    /// hence the `with` module
    #[serde(with = "batch_sizes_serde")]
    pub batch_sizes: [u32; ResponseMetrics::MAX_BATCH_SIZE],
}

impl Default for ResponseMetrics {
    fn default() -> Self {
        Self {
            num_responses: 0,
            num_bytes_sent: 0,
            batch_sizes: [0; ResponseMetrics::MAX_BATCH_SIZE],
        }
    }
}

/// serde derive lacks impls for arrays longer than 32; the wire format is the
/// same JSON array of numbers as the former `Vec<usize>`
mod batch_sizes_serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::ResponseMetrics;

    pub fn serialize<S: Serializer>(
        value: &[u32; ResponseMetrics::MAX_BATCH_SIZE],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(value.iter())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u32; ResponseMetrics::MAX_BATCH_SIZE], D::Error> {
        let values: Vec<u32> = Vec::deserialize(deserializer)?;
        values
            .try_into()
            .map_err(|v: Vec<u32>| D::Error::invalid_length(v.len(), &"64 batch size counters"))
    }
}

impl ResponseMetrics {
    pub const MAX_BATCH_SIZE: usize = 64;

    pub fn add_batch_size(&mut self, batch_size: u8) {
        debug_assert!(
            batch_size > 0 && batch_size <= Self::MAX_BATCH_SIZE as u8,
            "Invalid batch size: {batch_size}"
        );

        self.num_responses += batch_size as usize;
        self.batch_sizes[batch_size as usize - 1] += 1;
    }

    pub fn add_bytes_sent(&mut self, num_bytes: usize) {
        self.num_bytes_sent += num_bytes;
    }

    pub fn counts_as_string(&self) -> String {
        self.batch_sizes
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .map(|(size, count)| format!("{}: {}", size + 1, count))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn reset_metrics(&mut self) {
        *self = Self::default();
    }
}

impl AddAssign for ResponseMetrics {
    fn add_assign(&mut self, rhs: Self) {
        self.num_responses += rhs.num_responses;
        self.num_bytes_sent += rhs.num_bytes_sent;

        for (idx, &count) in rhs.batch_sizes.iter().enumerate() {
            self.batch_sizes[idx] += count;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_network_metrics_add_assign() {
        let mut metrics1 = NetworkMetrics {
            num_recv_wouldblock: 10,
            num_successful_sends: 20,
            num_failed_sends: 5,
            num_failed_polls: 2,
            num_failed_recvs: 3,
            num_oversized_dropped: 4,
        };

        let metrics2 = NetworkMetrics {
            num_recv_wouldblock: 5,
            num_successful_sends: 15,
            num_failed_sends: 3,
            num_failed_polls: 1,
            num_failed_recvs: 2,
            num_oversized_dropped: 6,
        };

        metrics1 += metrics2;

        assert_eq!(metrics1.num_recv_wouldblock, 15);
        assert_eq!(metrics1.num_successful_sends, 35);
        assert_eq!(metrics1.num_failed_sends, 8);
        assert_eq!(metrics1.num_failed_polls, 3);
        assert_eq!(metrics1.num_failed_recvs, 5);
        assert_eq!(metrics1.num_oversized_dropped, 10);
    }

    #[test]
    fn test_request_metrics_add_assign() {
        let mut metrics1 = RequestMetrics {
            num_ok_requests: 100,
            num_bad_requests: 10,
            num_runt_requests: 5,
            num_oversized_requests: 2,
            num_srv_mismatch: 4,
            num_no_common_version: 6,
            num_version_overflow: 1,
        };

        let metrics2 = RequestMetrics {
            num_ok_requests: 50,
            num_bad_requests: 5,
            num_runt_requests: 3,
            num_oversized_requests: 1,
            num_srv_mismatch: 2,
            num_no_common_version: 3,
            num_version_overflow: 2,
        };

        metrics1 += metrics2;

        assert_eq!(metrics1.num_ok_requests, 150);
        assert_eq!(metrics1.num_bad_requests, 15);
        assert_eq!(metrics1.num_runt_requests, 8);
        assert_eq!(metrics1.num_oversized_requests, 3);
        assert_eq!(metrics1.num_version_overflow, 3);
    }

    #[test]
    fn test_response_metrics_add_assign() {
        let mut metrics1 = ResponseMetrics::default();
        metrics1.add_batch_size(10);
        metrics1.add_batch_size(20);
        metrics1.add_batch_size(20);
        metrics1.add_bytes_sent(1024);

        let mut metrics2 = ResponseMetrics::default();
        metrics2.add_batch_size(5);
        metrics2.add_batch_size(10);
        metrics2.add_bytes_sent(1024);

        metrics1 += metrics2;

        assert_eq!(metrics1.num_responses, 65);
        assert_eq!(metrics1.num_bytes_sent, 2048);
        let counts = &metrics1.batch_sizes;
        assert_eq!(counts.len(), ResponseMetrics::MAX_BATCH_SIZE);
        assert_eq!(counts[5 - 1], 1);
        assert_eq!(counts[10 - 1], 2);
        assert_eq!(counts[20 - 1], 2);
    }
}
