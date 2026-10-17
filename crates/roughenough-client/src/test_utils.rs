//! Shared test fixtures: [`Measurement`]s produced by exchanges with an in-process server.

use roughenough_common::crypto::{calculate_chained_nonce, random_bytes};
use roughenough_protocol::ToFrame;
use roughenough_protocol::tags::Nonce;
use roughenough_server::test_utils::TestContext;

use crate::measurement::Measurement;

pub const BASE_TIME: u64 = 1_700_000_000;

/// A validated exchange with an in-process server whose clock reads `midpoint`.
pub fn measurement(midpoint: u64) -> Measurement {
    let mut ctx = TestContext::new(64);
    let (req, resp) = ctx.create_interaction_pair(midpoint);
    let resp_bytes = resp.as_frame_bytes().unwrap();
    let pubkey = ctx.key_source.public_key();

    Measurement::new(
        "127.0.0.1:8000".parse().unwrap(),
        "test".to_string(),
        Some(pubkey),
        req,
        resp,
        resp_bytes,
        None,
    )
}

/// Arbitrary MIDP/RADI written after the exchange, so extreme values never reach the test
/// server's clock. Signatures no longer verify; use only for causality arithmetic.
pub fn hostile_measurement(midpoint: u64, radius: u32) -> Measurement {
    let mut ctx = TestContext::new(64);
    let (req, mut resp) = ctx.create_interaction_pair(1000);

    let mut srep = resp.srep().clone();
    srep.set_midp(midpoint);
    srep.set_radi(radius);
    resp.set_srep(srep);

    let resp_bytes = resp.as_frame_bytes().unwrap();
    let pubkey = ctx.key_source.public_key();

    Measurement::new(
        "127.0.0.1:8000".parse().unwrap(),
        "test".to_string(),
        Some(pubkey),
        req,
        resp,
        resp_bytes,
        None,
    )
}

/// A nonce-chained sequence (RFC 8.2): entry 0 uses a random nonce and `first_rand` as its
/// (meaningless) rand; entry k uses H(response_{k-1} || rand_k). All entries share one
/// server identity (seed [42; 32]) and BASE_TIME delegation epoch.
pub fn chained_measurements(midpoints: &[u64], first_rand: Option<[u8; 32]>) -> Vec<Measurement> {
    let mut prior_response: Option<Vec<u8>> = None;
    let mut measurements = Vec::new();

    for &midpoint in midpoints {
        // A fixed epoch keeps delegations and response midpoints consistent even when
        // fixture construction crosses a wall-clock second boundary
        let mut ctx = TestContext::new_at(1, BASE_TIME);

        let (nonce, rand_value) = match prior_response.as_deref() {
            Some(prior) => {
                let rand = random_bytes::<32>();
                (calculate_chained_nonce(prior, &rand), Some(rand))
            }
            None => (Nonce::from(random_bytes::<32>()), first_rand),
        };

        let (request, response) = ctx.create_interaction_pair_with_nonce(midpoint, &nonce);
        let response_bytes = response.as_frame_bytes().unwrap();

        let measurement = Measurement::new(
            "127.0.0.1:2003".parse().unwrap(),
            "test".to_string(),
            Some(ctx.key_source.public_key()),
            request,
            response,
            response_bytes.clone(),
            rand_value,
        );

        prior_response = Some(response_bytes);
        measurements.push(measurement);
    }

    measurements
}
