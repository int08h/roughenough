//! Chained multi-server measurements that detect violations of causal ordering.

use roughenough_common::crypto::{calculate_chained_nonce, random_bytes};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::Request;
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::Nonce;
use roughenough_protocol::{FromFrame, ToFrame};

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
/// See also [`validate_causality`](crate::validation::ResponseValidator::validate_causality).
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
    /// The returned [`Measurement`]s can be validated using [`validate_causality`](crate::validation::ResponseValidator::validate_causality).
    pub fn run(&mut self, rounds: usize) -> Result<Vec<Measurement>, ClientError> {
        for client in &self.clients {
            if client.public_key.is_none() {
                return Err(ClientError::InvalidConfiguration(format!(
                    "measurement sequence requires all servers to have public keys ('{}' missing public key)",
                    client.hostname
                )));
            }
        }

        let mut measurements = Vec::new();
        let mut prior_response: Option<Response> = None;

        for _round in 0..rounds {
            for client in &self.clients {
                let measurement = self.query(client, prior_response)?;
                prior_response = Some(measurement.response().clone());
                measurements.push(measurement);
            }
        }

        Ok(measurements)
    }

    fn query(
        &self,
        client: &Client,
        prior_response: Option<Response>,
    ) -> Result<Measurement, ClientError> {
        let (nonce, rand_value) = Self::generate_nonce(&prior_response)?;

        let srv_commit = client.srv_commit.clone().unwrap();
        let request = Request::new_with_server(&nonce, &srv_commit);

        let request_bytes = request.as_frame_bytes()?;
        let _nbytes = client.transport.send(&request_bytes, client.server)?;

        let mut buf = [0u8; 1024];
        let (nbytes, _addr) = client.transport.recv(&mut buf)?;
        let mut cursor = ParseCursor::new(&mut buf[..nbytes]);
        let response = Response::from_frame(&mut cursor)?;

        // Validate the response
        let _midpoint = client.validator.validate(&request_bytes, &response)?;

        Measurement::builder()
            .server(client.server)
            .hostname(client.hostname.clone())
            .public_key(client.public_key)
            .request(request)
            .response(response)
            .rand_value(rand_value)
            .prior_response(prior_response.clone())
            .build()
    }

    /// If we have a prior response, then generate `H(prior_response || chaining_rand)`. Otherwise
    /// generate a random nonce.
    fn generate_nonce(
        prior_response: &Option<Response>,
    ) -> Result<(Nonce, Option<[u8; 32]>), ClientError> {
        let (nonce, rand) = if let Some(prior_response) = &prior_response {
            let rand = random_bytes::<32>();
            let nonce = calculate_chained_nonce(prior_response, &rand);

            (nonce, Some(rand))
        } else {
            let nonce = Nonce::from(random_bytes::<32>());
            (nonce, None)
        };

        Ok((nonce, rand))
    }
}
