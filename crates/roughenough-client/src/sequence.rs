//! Chained multi-server measurements that detect violations of causal ordering.

use roughenough_common::crypto::{calculate_chained_nonce, random_bytes};
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::request::{MAX_RESPONSE_SIZE, Request};
use roughenough_protocol::response::Response;
use roughenough_protocol::tags::Nonce;
use roughenough_protocol::{FromFrame, ToFrame};

use crate::measurement::Measurement;
use crate::validation::ValidationError;
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
        let mut prior_response: Option<Vec<u8>> = None;

        for _round in 0..rounds {
            for client in &self.clients {
                let measurement = self.query(client, prior_response.as_deref())?;
                prior_response = Some(measurement.response_bytes().to_vec());
                measurements.push(measurement);
            }
        }

        Ok(measurements)
    }

    fn query(
        &self,
        client: &Client,
        prior_response: Option<&[u8]>,
    ) -> Result<Measurement, ClientError> {
        let (nonce, rand_value) = Self::generate_nonce(prior_response);

        let srv_commit = client.srv_commit.unwrap();
        let request = match &client.versions {
            Some(versions) => Request::new_with_server_and_versions(&nonce, &srv_commit, versions),
            None => Request::new_with_server(&nonce, &srv_commit),
        };

        let request_bytes = request.as_frame_bytes()?;
        let _nbytes = client.transport.send(&request_bytes, client.server)?;

        let (response, response_bytes) = Self::recv_validated(client, &request_bytes)?;

        Measurement::builder()
            .server(client.server)
            .hostname(client.hostname.clone())
            .public_key(client.public_key)
            .request(request)
            .response(response)
            .response_bytes(response_bytes)
            .rand_value(rand_value)
            .build()
    }

    /// Receive datagrams until one validates against this round's request.
    fn recv_validated(
        client: &Client,
        request_bytes: &[u8],
    ) -> Result<(Response, Vec<u8>), ClientError> {
        loop {
            let mut buf = [0u8; MAX_RESPONSE_SIZE];
            let (nbytes, _addr) = client.transport.recv(&mut buf)?;
            let response_bytes = buf[..nbytes].to_vec();

            let mut cursor = ParseCursor::new(&mut buf[..nbytes]);
            let response = Response::from_frame(&mut cursor)?;

            match client
                .validator
                .validate(request_bytes, &response_bytes, &response)
            {
                Ok(_midpoint) => return Ok((response, response_bytes)),
                // Stale datagram from a prior round: drain it and keep waiting
                Err(ValidationError::FailedProof(_)) => continue,
                Err(e) => return Err(e.into()),
            }
        }
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
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::SocketAddr;

    use roughenough_protocol::tags::ProtocolVersion;
    use roughenough_protocol::util::ClockSource;
    use roughenough_server::test_utils::TestContext;

    use super::*;
    use crate::transport::ClientTransport;

    fn test_addr() -> SocketAddr {
        "127.0.0.1:2003".parse().unwrap()
    }

    struct InProcessTransport {
        ctx: RefCell<TestContext>,
        last_request: RefCell<Vec<u8>>,
        pre_queue: RefCell<VecDeque<Vec<u8>>>,
        starve: bool,
    }

    impl InProcessTransport {
        fn new(ctx: TestContext) -> Self {
            Self {
                ctx: RefCell::new(ctx),
                last_request: RefCell::new(Vec::new()),
                pre_queue: RefCell::new(VecDeque::new()),
                starve: false,
            }
        }
    }

    impl ClientTransport for InProcessTransport {
        fn send(&self, data: &[u8], _addr: SocketAddr) -> Result<usize, ClientError> {
            *self.last_request.borrow_mut() = data.to_vec();
            Ok(data.len())
        }

        fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError> {
            if let Some(canned) = self.pre_queue.borrow_mut().pop_front() {
                buf[..canned.len()].copy_from_slice(&canned);
                return Ok((canned.len(), test_addr()));
            }

            if self.starve {
                return Err(ClientError::ServerTimeout);
            }

            let frame = self.last_request.borrow().clone();
            let mut parse_buf = frame.clone();
            let mut cursor = ParseCursor::new(&mut parse_buf);
            let request = Request::from_frame(&mut cursor).expect("mock got a valid request");

            let mut ctx = self.ctx.borrow_mut();
            ctx.response_handler.clear();
            assert!(ctx.response_handler.add_request(
                &frame,
                request,
                ProtocolVersion::DRAFT,
                test_addr(),
            ));

            let mut out = Vec::new();
            ctx.response_handler
                .process_responses(|_addr, bytes| out.extend_from_slice(bytes));

            buf[..out.len()].copy_from_slice(&out);
            Ok((out.len(), test_addr()))
        }
    }

    /// A client answered by an in-process server, with `stale_count` valid
    /// responses for an unrelated nonce delivered ahead of the real answer
    fn client_with_stale_datagrams(stale_count: usize, starve: bool) -> Client {
        let mut ctx = TestContext::new(64);
        let now = ClockSource::System.epoch_seconds();

        // A signed response for a different request: signatures verify but
        // the Merkle proof cannot match the round's nonce
        let (_req, stale) = ctx.create_interaction_pair(now);
        let stale_bytes = stale.as_frame_bytes().unwrap();

        let pub_key = ctx.key_source.public_key();
        let mut transport = InProcessTransport::new(ctx);
        for _ in 0..stale_count {
            transport.pre_queue.get_mut().push_back(stale_bytes.clone());
        }
        transport.starve = starve;

        Client::builder(test_addr())
            .public_key(pub_key)
            .transport(Box::new(transport))
            .build()
    }

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
        let mut sequence = MeasurementSequence::new(clients);

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
        let mut sequence = MeasurementSequence::new(clients);

        let measurements = sequence.run(1).unwrap();
        assert_eq!(measurements.len(), 1);
    }

    #[test]
    fn only_stale_datagrams_end_in_timeout() {
        // Draining must be bounded by the transport timeout, not loop forever
        // or accept a mismatched response
        let clients = vec![client_with_stale_datagrams(2, true)];
        let mut sequence = MeasurementSequence::new(clients);

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
        let mut sequence = MeasurementSequence::new(vec![client]);

        match sequence.run(1) {
            Err(ClientError::InvalidConfiguration(msg)) => {
                assert!(msg.contains("public key"));
            }
            other => panic!("expected InvalidConfiguration, got {other:?}"),
        }
    }
}
