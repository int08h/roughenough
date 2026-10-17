//! Chained multi-server measurements that detect violations of causal ordering.

use roughenough_common::crypto::{calculate_chained_nonce, random_bytes};
use roughenough_protocol::tags::Nonce;

use crate::measurement::Measurement;
use crate::{Client, ClientError};

/// A chained multi-server sequential measurement that detects violations of causal ordering.
///
/// The first request in the sequence uses a randomly generated nonce. The second query uses
/// `H(prior_response || chaining_rand)` where `chaining_rand` is a random 32-byte value and
/// `prior_response` is the response to the first probe. Each subsequent query uses
/// `H(prior_response || chaining_rand)` for the previous response and a new 32-byte random
/// value.
///
/// For each pair of responses `(i, j)`, where `i` was received before `j`, `MIDP_i-RADI_i` is
/// confirmed to be less than or equal to `MIDP_j+RADI_j`. If all checks pass, the times are
/// consistent with causal ordering.
///
/// See also [`CausalityViolation::find`](crate::validation::CausalityViolation::find).
pub struct MeasurementSequence {
    clients: Vec<Client>,
}

impl MeasurementSequence {
    pub fn new(clients: Vec<Client>) -> Self {
        Self { clients }
    }

    /// Run chained measurements across all servers for the specified number of rounds, returning
    /// all measurements collected during the run.
    ///
    /// The returned [`Measurement`]s can be validated using [`CausalityViolation::find`](crate::validation::CausalityViolation::find).
    pub fn run(&self, rounds: usize) -> Result<Vec<Measurement>, ClientError> {
        for client in &self.clients {
            if client.public_key().is_none() {
                let msg = format!(
                    "measurement sequence requires all servers to have public keys ('{}' missing public key)",
                    client.hostname()
                );
                return Err(ClientError::InvalidConfiguration(msg));
            }
        }

        let mut measurements = Vec::new();
        let mut prior_response: Option<Vec<u8>> = None;

        for _round in 0..rounds {
            for client in &self.clients {
                let (nonce, rand_value) = Self::generate_nonce(prior_response.as_deref());
                let measurement = client.exchange(nonce, rand_value)?;
                prior_response = Some(measurement.response_bytes().to_vec());
                measurements.push(measurement);
            }
        }

        Ok(measurements)
    }

    /// If we have a prior response, then generate `H(prior_response || chaining_rand)`. Otherwise
    /// generate a random nonce. `prior_response` is the prior response packet exactly as received.
    fn generate_nonce(prior_response: Option<&[u8]>) -> (Nonce, Option<[u8; 32]>) {
        match prior_response {
            Some(prior_frame) => {
                let rand = random_bytes::<32>();
                let nonce = calculate_chained_nonce(prior_frame, &rand);
                (nonce, Some(rand))
            }
            None => (Nonce::from(random_bytes::<32>()), None),
        }
    }
}

#[cfg(test)]
mod tests {
    use roughenough_server::test_utils::TestContext;

    use super::*;
    use crate::transport::testing::{InProcessTransport, client_with_stale_datagrams, test_addr};

    #[test]
    fn chained_nonce_hashes_full_prior_frame() {
        // RFC 8.2: the chained nonce is H(prior response packet || rand),
        // over the packet exactly as received including the framing
        let prior_frame = vec![0x5au8; 420];
        let (nonce, rand) = MeasurementSequence::generate_nonce(Some(&prior_frame));

        let rand = rand.expect("chained nonce must carry its rand value");
        assert_eq!(nonce, calculate_chained_nonce(&prior_frame, &rand));
    }

    #[test]
    fn first_nonce_is_unchained() {
        let (_nonce, rand) = MeasurementSequence::generate_nonce(None);
        assert!(rand.is_none(), "the first nonce has no chaining rand");
    }

    #[test]
    fn run_chains_nonces_across_measurements() {
        let clients = vec![
            client_with_stale_datagrams(0, false),
            client_with_stale_datagrams(0, false),
        ];
        let sequence = MeasurementSequence::new(clients);

        let measurements = sequence.run(1).unwrap();
        assert_eq!(measurements.len(), 2);
        assert!(measurements[0].rand_value().is_none());

        // The second request's nonce must be derived from the first response
        let rand = measurements[1].rand_value().expect("chained rand");
        let expected = calculate_chained_nonce(measurements[0].response_bytes(), rand);
        assert_eq!(*measurements[1].request().nonc(), expected);
    }

    #[test]
    fn stale_datagram_is_drained_not_fatal() {
        // A duplicated datagram from an earlier round arrives first; the
        // sequence must skip it and complete with the real response
        let clients = vec![client_with_stale_datagrams(2, false)];
        let sequence = MeasurementSequence::new(clients);

        let measurements = sequence.run(1).unwrap();
        assert_eq!(measurements.len(), 1);
    }

    #[test]
    fn only_stale_datagrams_end_in_timeout() {
        // Draining must be bounded by the transport timeout, not loop forever
        // or accept a mismatched response
        let clients = vec![client_with_stale_datagrams(2, true)];
        let sequence = MeasurementSequence::new(clients);

        match sequence.run(1) {
            Err(ClientError::ServerTimeout) => {}
            other => panic!("expected ServerTimeout, got {other:?}"),
        }
    }

    #[test]
    fn missing_public_key_is_rejected() {
        let ctx = TestContext::new(64);
        let client = Client::builder(test_addr())
            .transport(Box::new(InProcessTransport::new(ctx)))
            .build();
        let sequence = MeasurementSequence::new(vec![client]);

        match sequence.run(1) {
            Err(ClientError::InvalidConfiguration(msg)) => {
                assert!(msg.contains("public key"));
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }
}
