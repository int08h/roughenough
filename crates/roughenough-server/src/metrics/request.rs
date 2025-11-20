use std::ops::AddAssign;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct RequestMetrics {
    pub num_ok_requests: usize,
    pub num_bad_requests: usize,
    pub num_runt_requests: usize,
    pub num_jumbo_requests: usize,
}

impl AddAssign for RequestMetrics {
    fn add_assign(&mut self, rhs: Self) {
        self.num_ok_requests += rhs.num_ok_requests;
        self.num_bad_requests += rhs.num_bad_requests;
        self.num_runt_requests += rhs.num_runt_requests;
        self.num_jumbo_requests += rhs.num_jumbo_requests;
    }
}

#[test]
fn test_request_metrics_add_assign() {
    let mut metrics1 = RequestMetrics {
        num_ok_requests: 100,
        num_bad_requests: 10,
        num_runt_requests: 5,
        num_jumbo_requests: 2,
    };

    let metrics2 = RequestMetrics {
        num_ok_requests: 50,
        num_bad_requests: 5,
        num_runt_requests: 3,
        num_jumbo_requests: 1,
    };

    metrics1 += metrics2;

    assert_eq!(metrics1.num_ok_requests, 150);
    assert_eq!(metrics1.num_bad_requests, 15);
    assert_eq!(metrics1.num_runt_requests, 8);
    assert_eq!(metrics1.num_jumbo_requests, 3);
}