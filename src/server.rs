// Copyright 2017-2022 int08h LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//!
//! Implements the Roughenough server functionality.
//!

use std::io::ErrorKind;
use std::io::Write;
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::ServerConfig;
use crate::key::LongTermKey;
use crate::kms;
use crate::request;
use crate::responder::Responder;
use crate::stats::{AggregatedStats, ClientStats, PerClientStats, ServerStats, StatsQueue};
use crate::version::Version;
use mio::net::{TcpListener, UdpSocket};
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::timer::Timer;
use rand::{thread_rng, RngCore};

// mio event registrations
const EVT_MESSAGE: Token = Token(0);
const EVT_STATUS_UPDATE: Token = Token(1);
const EVT_HEALTH_CHECK: Token = Token(2);

// Canned response to health check request
const HTTP_RESPONSE: &str = "HTTP/1.1 200 OK\nContent-Length: 0\nConnection: close\n\n";

/// The main Roughenough server instance.
///
/// The [ServerConfig](../config/trait.ServerConfig.html) trait specifies the required and optional
/// parameters available for configuring a Roughenoguh server instance.
///
/// Implementations of `ServerConfig` obtain configurations from different back-end sources
/// such as files or environment variables.
///
/// See [the config module](../config/index.html) for more information.
///
pub struct Server {
    batch_size: u8,
    socket: UdpSocket,
    health_listener: Option<TcpListener>,
    poll_duration: Option<Duration>,
    poll: Poll,
    responder_ietf: Responder,
    responder_classic: Responder,
    buf: [u8; 65_536],
    thread_name: String,
    srv_value: Vec<u8>,

    stats_pub_freq: Duration,
    stats_pub_timer: Timer<()>,
    stats_recorder: Box<dyn ServerStats>,
    stats_queue: Arc<StatsQueue>,

    // Used to send requests to ourselves in fuzzing mode
    #[cfg(feature = "fuzzing")]
    fake_client_socket: UdpSocket,
}

impl Server {
    ///
    /// Create a new server instance from the provided
    /// [`ServerConfig`](../config/trait.ServerConfig.html) trait object instance.
    ///
    pub fn new(config: &dyn ServerConfig, socket: UdpSocket, queue: Arc<StatsQueue>) -> Server {
        let stats_freq = config.status_interval() / 10;
        let delay = Self::compute_delay(stats_freq);
        let mut timer: Timer<()> = Timer::default();
        timer.set_timeout(delay, ());

        let poll = Poll::new().unwrap();
        poll.register(&socket, EVT_MESSAGE, Ready::readable(), PollOpt::edge())
            .unwrap();
        poll.register(
            &timer,
            EVT_STATUS_UPDATE,
            Ready::readable(),
            PollOpt::edge(),
        )
        .unwrap();

        let health_listener = if let Some(hc_port) = config.health_check_port() {
            let hc_sock_addr: SocketAddr = format!("{}:{}", config.interface(), hc_port)
                .parse()
                .unwrap();

            let tcp_listener = TcpListener::bind(&hc_sock_addr)
                .expect("failed to bind TCP listener for health check");

            poll.register(
                &tcp_listener,
                EVT_HEALTH_CHECK,
                Ready::readable(),
                PollOpt::edge(),
            )
            .unwrap();

            Some(tcp_listener)
        } else {
            None
        };

        let stats: Box<dyn ServerStats> = if config.client_stats_enabled() {
            Box::new(PerClientStats::new())
        } else {
            Box::new(AggregatedStats::new())
        };

        let mut long_term_key = {
            let seed = kms::load_seed(config).expect("failed loading seed");
            LongTermKey::new(&seed)
        };

        let responder_ietf = Responder::new(Version::RfcDraft13, config, &mut long_term_key);
        let responder_classic = Responder::new(Version::Google, config, &mut long_term_key);

        let batch_size = config.batch_size();
        let thread_name = thread::current().name().unwrap().to_string();
        let poll_duration = Some(Duration::from_millis(100));
        let srv_value = long_term_key.srv_value().to_vec();

        Server {
            batch_size,
            socket,
            health_listener,
            poll_duration,
            poll,
            responder_ietf,
            responder_classic,
            buf: [0u8; 65_536],
            thread_name,
            srv_value,
            stats_pub_freq: stats_freq,
            stats_pub_timer: timer,
            stats_recorder: stats,
            stats_queue: queue,

            #[cfg(feature = "fuzzing")]
            fake_client_socket: UdpSocket::bind(&"127.0.0.1:0".parse().unwrap()).unwrap(),
        }
    }

    /// Returns a reference to the server's long-term public key
    pub fn get_public_key(&self) -> &str {
        self.responder_ietf.get_public_key()
    }

    #[cfg(feature = "fuzzing")]
    pub fn send_to_self(&mut self, data: &[u8]) {
        let res = self
            .fake_client_socket
            .send_to(data, &self.socket.local_addr().unwrap());
        info!("Sent to self: {:?}", res);
    }

    /// The main processing function for incoming connections. This method should be
    /// called repeatedly in a loop to process requests.
    ///
    pub fn process_events(&mut self, events: &mut Events) {
        self.poll
            .poll(events, self.poll_duration)
            .expect("server event poll failed; cannot recover");

        for msg in events.iter() {
            match msg.token() {
                EVT_MESSAGE => loop {
                    self.responder_ietf.reset();
                    self.responder_classic.reset();

                    let socket_now_empty = self.collect_requests();

                    self.responder_ietf.send_responses(&mut self.socket, &mut self.stats_recorder);
                    self.responder_classic.send_responses(&mut self.socket, &mut self.stats_recorder);

                    if socket_now_empty {
                        break;
                    }
                },
                EVT_HEALTH_CHECK => self.handle_health_check(),
                EVT_STATUS_UPDATE => self.send_client_stats(),
                _ => unreachable!(),
            }
        }
    }

    // Read and process client requests from socket until socket is empty or 'batch_size' number
    // of requests have been read.
    fn collect_requests(&mut self) -> bool {
        for i in 0..self.batch_size {
            match self.socket.recv_from(&mut self.buf) {
                Ok((num_bytes, src_addr)) => {
                    match request::nonce_from_request(&self.buf, num_bytes, &self.srv_value) {
                        // TODO(stuart) cleanup when RFC is ratified
                        Ok((nonce, Version::RfcDraft13)) => {
                            let request_bytes = &self.buf[..num_bytes];
                            self.responder_ietf.add_ietf_request(request_bytes, nonce, src_addr);
                            self.stats_recorder.add_ietf_request(&src_addr.ip());
                        }
                        Ok((nonce, Version::Google)) => {
                            self.responder_classic.add_classic_request(nonce, src_addr);
                            self.stats_recorder.add_classic_request(&src_addr.ip());
                        }
                        Err(e) => {
                            self.stats_recorder.add_invalid_request(&src_addr.ip(), &e);

                            debug!(
                                "Invalid request: '{:?}' ({} bytes) from {} (#{} in batch)",
                                e, num_bytes, src_addr, i
                            );
                        }
                    }
                }
                Err(e) => match e.kind() {
                    ErrorKind::WouldBlock => {
                        return true;
                    }
                    _ => {
                        error!("Error receiving from socket: {:?}: {:?}", e.kind(), e);
                        return false;
                    }
                },
            };
        }

        false
    }

    fn handle_health_check(&mut self) {
        let listener = self.health_listener.as_ref().unwrap();
        match listener.accept() {
            Ok((ref mut stream, src_addr)) => {
                info!("health check from {}", src_addr);
                self.stats_recorder.add_health_check(&src_addr.ip());

                match stream.write_all(HTTP_RESPONSE.as_bytes()) {
                    Ok(_) => (),
                    Err(e) => warn!("error writing health check {}", e),
                };

                match stream.shutdown(Shutdown::Both) {
                    Ok(_) => (),
                    Err(e) => warn!("error in health check socket shutdown {}", e),
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                debug!("blocking in TCP health check");
            }
            Err(e) => {
                warn!("unexpected health check error {}", e);
            }
        }
    }

    fn send_client_stats(&mut self) {
        let start = Instant::now();

        let clients: Vec<ClientStats> = self.stats_recorder
            .iter()
            .map(|(_, s)| *s).collect();

        let client_count = clients.len();
        if client_count > 0 {
            self.stats_queue.force_push(clients);
            self.stats_recorder.clear();
        }

        let delay = Self::compute_delay(self.stats_pub_freq);
        self.stats_pub_timer.set_timeout(delay, ());

        let elapsed = start.elapsed();
        debug!(
            "{} enqueued {} client stats in {:.3} seconds",
            self.thread_name(),
            client_count,
            elapsed.as_secs_f32()
        );
    }

    pub fn thread_name(&self) -> &str {
        &self.thread_name
    }

    fn compute_delay(base: Duration) -> Duration {
        if base.as_secs() < 1 {
            return base;
        }

        let mut jitter: u8 = 0;
        while jitter == 0 {
            jitter = (thread_rng().next_u32() & 0xff) as u8;
        }

        if jitter & 1 == 1 {
            base - Duration::from_millis(jitter as u64)
        } else {
            base + Duration::from_millis(jitter as u64)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::server::Server;
    use std::time::Duration;

    #[test]
    fn no_jitter_when_duration_lt_1sec() {
        assert_eq!(
            Server::compute_delay(Duration::from_millis(999)),
            Duration::from_millis(999)
        );
        assert_eq!(
            Server::compute_delay(Duration::from_millis(500)),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn jitter_is_added() {
        for i in 2..20 {
            let base = Duration::from_secs(i);
            let computed = Server::compute_delay(base);

            // jitter is always added, we never see the same value back
            assert_ne!(computed, base);

            // difference is always within 256 milliseconds
            let limit = Duration::from_millis(256);
            if base > computed {
                assert!(base - computed < limit);
            } else {
                assert!(computed - base < limit);
            }
        }
    }
}
