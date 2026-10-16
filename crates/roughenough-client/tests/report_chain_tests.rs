//! check that the client's malfeasance report construction agrees with
//! the reporting server's validation: every violation `validate_causality`
//! must produce a report `validate_report` accepts.

use data_encoding::BASE64;
use roughenough_client::test_utils::{BASE_TIME, chained_measurements};
use roughenough_client::{MalfeasanceReport, ResponseValidator};
use roughenough_reporting_server::validate_report;

#[test]
fn client_reports_are_accepted_by_reporting_server_validator() {
    let base = BASE_TIME;

    // Measurement 0 claims a time far ahead of measurements 1 and 2, so every
    // pair -- (0,1), (0,2), and (1,2) -- violates causality
    let measurements = chained_measurements(&[base + 2_000_000, base + 1_000_000, base], None);

    let violations = ResponseValidator::validate_causality(&measurements);
    assert_eq!(violations.len(), 3, "all three pairs violate causality");

    for violation in &violations {
        let report = MalfeasanceReport::from_violation(violation);

        let json = serde_json::to_string(&report).unwrap();
        let received: MalfeasanceReport = serde_json::from_str(&json).unwrap();

        validate_report(&received).unwrap_or_else(|e| {
            panic!(
                "report for violating pair ({}, {}) was rejected: {e}",
                violation.index_i(),
                violation.index_j()
            )
        });
    }
}

#[test]
fn client_report_for_violation_spanning_intermediate_measurement_is_accepted() {
    let base = BASE_TIME;

    // Only the (0, 2) pair violates: measurement 1 is consistent with both
    // neighbors
    let measurements = chained_measurements(&[base + 15, base + 8, base], None);

    let violations = ResponseValidator::validate_causality(&measurements);
    assert_eq!(violations.len(), 1, "only the (0, 2) pair violates");
    assert_eq!(violations[0].index_i(), 0);
    assert_eq!(violations[0].index_j(), 2);

    let report = MalfeasanceReport::from_violation(&violations[0]);
    assert_eq!(report.responses().len(), 3);

    assert_eq!(
        report.responses()[1].rand().unwrap(),
        BASE64.encode(measurements[1].rand_value().unwrap())
    );

    validate_report(&report).expect("chained report spanning three measurements must validate");
}
