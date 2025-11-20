use std::ops::AddAssign;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub num_recv_wouldblock: usize,
    pub num_successful_sends: usize,
    pub num_failed_sends: usize,
    pub num_failed_polls: usize,
    pub num_failed_recvs: usize,
}

impl AddAssign for NetworkMetrics {
    fn add_assign(&mut self, rhs: Self) {
        self.num_recv_wouldblock += rhs.num_recv_wouldblock;
        self.num_successful_sends += rhs.num_successful_sends;
        self.num_failed_sends += rhs.num_failed_sends;
        self.num_failed_polls += rhs.num_failed_polls;
        self.num_failed_recvs += rhs.num_failed_recvs;
    }
}

#[test]
fn test_network_metrics_add_assign() {
    let mut metrics1 = NetworkMetrics {
        num_recv_wouldblock: 10,
        num_successful_sends: 20,
        num_failed_sends: 5,
        num_failed_polls: 2,
        num_failed_recvs: 3,
    };

    let metrics2 = NetworkMetrics {
        num_recv_wouldblock: 5,
        num_successful_sends: 15,
        num_failed_sends: 3,
        num_failed_polls: 1,
        num_failed_recvs: 2,
    };

    metrics1 += metrics2;

    assert_eq!(metrics1.num_recv_wouldblock, 15);
    assert_eq!(metrics1.num_successful_sends, 35);
    assert_eq!(metrics1.num_failed_sends, 8);
    assert_eq!(metrics1.num_failed_polls, 3);
    assert_eq!(metrics1.num_failed_recvs, 5);
}