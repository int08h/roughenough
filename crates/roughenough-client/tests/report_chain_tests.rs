//! check that the client's malfeasance report construction agrees with
//! the reporting server's validation: every violation `validate_causality`
//! must produce a report `validate_report` accepts.

use data_encoding::BASE64;
use roughenough_client::measurement::Measurement;
use roughenough_client::{MalfeasanceReport, ResponseValidator};
use roughenough_common::crypto::{calculate_chained_nonce, random_bytes};
use roughenough_protocol::ToFrame;
use roughenough_protocol::tags::Nonce;
use roughenough_reporting_server::validate_report;
use roughenough_server::test_utils::TestContext;

fn create_chained_measurements(midpoints: &[u64]) -> Vec<Measurement> {
    let mut prior_response: Option<Vec<u8>> = None;
    let mut measurements = Vec::new();

    for &midpoint in midpoints {
        // one context per exchange; all contexts share a seed, so the
        // measurements present one server identity
        let mut ctx = TestContext::new(1);

        let (nonce, rand_value) = match prior_response.as_deref() {
            Some(prior) => {
                let rand = random_bytes::<32>();
                (calculate_chained_nonce(prior, &rand), Some(rand))
            }
            None => (Nonce::from(random_bytes::<32>()), None),
        };

        let (request, response) = ctx.create_interaction_pair_with_nonce(midpoint, &nonce);
        let response_bytes = response.as_frame_bytes().unwrap();

        let measurement = Measurement::builder()
            .server("127.0.0.1:2003".parse().unwrap())
            .hostname("test".to_string())
            .public_key(Some(ctx.key_source.public_key()))
            .request(request)
            .response(response)
            .response_bytes(response_bytes.clone())
            .rand_value(rand_value)
            .build()
            .unwrap();

        prior_response = Some(response_bytes);
        measurements.push(measurement);
    }

    measurements
}

#[test]
fn client_reports_are_accepted_by_reporting_server_validator() {
    let base = TestContext::new(1).clock.epoch_seconds();

    // Measurement 0 claims a time far ahead of measurements 1 and 2, so every
    // pair -- (0,1), (0,2), and (1,2) -- violates causality
    let measurements = create_chained_measurements(&[base + 2_000_000, base + 1_000_000, base]);

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
    let base = TestContext::new(1).clock.epoch_seconds();

    // Only the (0, 2) pair violates: measurement 1 is consistent with both
    // neighbors
    let measurements = create_chained_measurements(&[base + 15, base + 8, base]);

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
