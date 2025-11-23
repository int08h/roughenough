use std::ops::AddAssign;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub num_recv_wouldblock: usize,
    pub num_successful_sends: usize,
    pub num_failed_sends: usize,
    pub num_failed_polls: usize,
    pub num_failed_recvs: usize,
    /// Number of recv syscalls made (for backend comparison)
    pub num_recv_syscalls: usize,
    /// Number of send syscalls made (for backend comparison)
    pub num_send_syscalls: usize,
}

impl AddAssign for NetworkMetrics {
    fn add_assign(&mut self, rhs: Self) {
        self.num_recv_wouldblock += rhs.num_recv_wouldblock;
        self.num_successful_sends += rhs.num_successful_sends;
        self.num_failed_sends += rhs.num_failed_sends;
        self.num_failed_polls += rhs.num_failed_polls;
        self.num_failed_recvs += rhs.num_failed_recvs;
        self.num_recv_syscalls += rhs.num_recv_syscalls;
        self.num_send_syscalls += rhs.num_send_syscalls;
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
        num_recv_syscalls: 100,
        num_send_syscalls: 50,
    };

    let metrics2 = NetworkMetrics {
        num_recv_wouldblock: 5,
        num_successful_sends: 15,
        num_failed_sends: 3,
        num_failed_polls: 1,
        num_failed_recvs: 2,
        num_recv_syscalls: 80,
        num_send_syscalls: 40,
    };

    metrics1 += metrics2;

    assert_eq!(metrics1.num_recv_wouldblock, 15);
    assert_eq!(metrics1.num_successful_sends, 35);
    assert_eq!(metrics1.num_failed_sends, 8);
    assert_eq!(metrics1.num_failed_polls, 3);
    assert_eq!(metrics1.num_failed_recvs, 5);
    assert_eq!(metrics1.num_recv_syscalls, 180);
    assert_eq!(metrics1.num_send_syscalls, 90);
}
