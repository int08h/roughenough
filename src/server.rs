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
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use humansize::{file_size_opts as fsopts, FileSize};
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio::net::{TcpListener, UdpSocket};
use mio_extras::timer::Timer;

use crate::config::ServerConfig;
use crate::key::LongTermKey;
use crate::kms;
use crate::request;
use crate::responder::Responder;
use crate::stats::{AggregatedStats, ClientStatEntry, PerClientStats, ServerStats};
use crate::version::Version;

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
    socket: Arc<UdpSocket>,
    health_listener: Option<TcpListener>,
    poll_duration: Option<Duration>,
    status_interval: Duration,
    timer: Timer<()>,
    poll: Poll,
    responder_rfc: Responder,
    responder_classic: Responder,
    buf: [u8; 65_536],
    thread_name: String,

    stats: Box<dyn ServerStats>,

    // Used to send requests to ourselves in fuzzing mode
    #[cfg(fuzzing)]
    fake_client_socket: UdpSocket,
}

impl Server {
    ///
    /// Create a new server instance from the provided
    /// [`ServerConfig`](../config/trait.ServerConfig.html) trait object instance.
    ///
    pub fn new(config: &dyn ServerConfig, socket: Arc<UdpSocket>) -> Server {
        // let sock_addr = config.udp_socket_addr().expect("udp sock addr");
        // let socket = UdpSocket::bind(&sock_addr).expect("failed to bind to socket");

        let poll_duration = Some(Duration::from_millis(100));

        let mut timer: Timer<()> = Timer::default();
        timer.set_timeout(config.status_interval(), ());

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

        let responder_rfc = Responder::new(Version::Rfc, config, &mut long_term_key);
        let responder_classic = Responder::new(Version::Classic, config, &mut long_term_key);

        let batch_size = config.batch_size();
        let status_interval = config.status_interval();
        let thread_name = thread::current().name().unwrap().to_string();

        Server {
            batch_size,
            socket,
            health_listener,
            poll_duration,
            status_interval,
            timer,
            poll,
            responder_rfc,
            responder_classic,
            buf: [0u8; 65_536],
            thread_name,

            stats,

            #[cfg(fuzzing)]
            fake_client_socket: UdpSocket::bind(&"127.0.0.1:0".parse().unwrap()).unwrap(),
        }
    }

    /// Returns a reference to the server's long-term public key
    pub fn get_public_key(&self) -> &str {
        &self.responder_rfc.get_public_key()
    }

    #[cfg(fuzzing)]
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
                    self.responder_rfc.reset();
                    self.responder_classic.reset();

                    let socket_now_empty = self.collect_requests();

                    let sock_copy = Arc::get_mut(&mut self.socket).unwrap();
                    self.responder_rfc.send_responses(sock_copy, &mut self.stats);
                    self.responder_classic.send_responses(sock_copy, &mut self.stats);

                    if socket_now_empty {
                        break;
                    }
                },
                EVT_HEALTH_CHECK => self.handle_health_check(),
                EVT_STATUS_UPDATE => self.handle_status_update(),
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
                    match request::nonce_from_request(&self.buf, num_bytes) {
                        Ok((nonce, Version::Rfc)) => {
                            self.responder_rfc.add_request(nonce, src_addr);
                            self.stats.add_rfc_request(&src_addr.ip());
                        }
                        Ok((nonce, Version::Classic)) => {
                            self.responder_classic.add_request(nonce, src_addr);
                            self.stats.add_classic_request(&src_addr.ip());
                        }
                        Err(e) => {
                            self.stats.add_invalid_request(&src_addr.ip());

                            debug!("Invalid request: '{:?}' ({} bytes) from {} (#{} in batch)",
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
                self.stats.add_health_check(&src_addr.ip());

                match stream.write(HTTP_RESPONSE.as_bytes()) {
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

    fn handle_status_update(&mut self) {
        let mut vec: Vec<(&IpAddr, &ClientStatEntry)> = self.stats.iter().collect();
        // sort in descending order
        vec.sort_by(|lhs, rhs| {
            let lhs_total = lhs.1.classic_requests + lhs.1.rfc_requests;
            let rhs_total = rhs.1.classic_requests + rhs.1.rfc_requests;
            rhs_total.cmp(&lhs_total)
        });

        for (addr, counts) in vec {
            info!(
                "{:16}: {} classic req, {} rfc req; {} invalid requests; {} classic resp, {} rfc resp ({} sent); {} failed sends",
                format!("{}", addr),
                counts.classic_requests,
                counts.rfc_requests,
                counts.invalid_requests,
                counts.classic_responses_sent,
                counts.rfc_responses_sent,
                counts.bytes_sent.file_size(fsopts::BINARY).unwrap(),
                counts.failed_send_attempts
            );
        }

        info!(
            "Totals: {} unique clients; {} total req ({} classic req, {} rfc req); {} invalid requests; {} total resp ({} classic resp, {} rfc resp); {} sent; {} failed sends",
            self.stats.total_unique_clients(),
            self.stats.total_valid_requests(),
            self.stats.num_classic_requests(),
            self.stats.num_rfc_requests(),
            self.stats.total_invalid_requests(),
            self.stats.total_responses_sent(),
            self.stats.num_classic_responses_sent(),
            self.stats.num_rfc_responses_sent(),
            self.stats.total_bytes_sent().file_size(fsopts::BINARY).unwrap(),
            self.stats.total_failed_send_attempts()
        );

        self.stats.clear();
        self.timer.set_timeout(self.status_interval, ());
    }

    pub fn thread_name(&self) -> &str {
        &self.thread_name
    }
}
