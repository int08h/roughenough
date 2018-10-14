// Copyright 2017-2018 int08h LLC
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
//! Roughtime server
//!
//! # Configuration
//! The `roughenough` server is configured via a YAML config file. See the documentation
//! for [FileConfig](struct.FileConfig.html) for details.
//!
//! To run the server:
//!
//! ```bash
//! $ cargo run --release --bin server /path/to/config.file
//! ```
//!

extern crate byteorder;
extern crate ctrlc;
extern crate hex;
#[macro_use]
extern crate log;
extern crate mio;
extern crate mio_extras;
extern crate ring;
extern crate roughenough;
extern crate simple_logger;
extern crate time;
extern crate untrusted;
extern crate yaml_rust;

use std::env;
use std::io::ErrorKind;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use mio_extras::timer::Timer;

use byteorder::{LittleEndian, WriteBytesExt};

use roughenough::config;
use roughenough::config::ServerConfig;
use roughenough::kms;
use roughenough::key::{LongTermKey, OnlineKey};
use roughenough::merkle::MerkleTree;
use roughenough::{Error, RtMessage, Tag};
use roughenough::{MIN_REQUEST_LENGTH, VERSION};

const MESSAGE: Token = Token(0);
const STATUS: Token = Token(1);

fn make_response(srep: &RtMessage, cert_bytes: &[u8], path: &[u8], idx: u32) -> RtMessage {
    let mut index = [0; 4];
    (&mut index as &mut [u8])
        .write_u32::<LittleEndian>(idx)
        .unwrap();

    let sig_bytes = srep.get_field(Tag::SIG).unwrap();
    let srep_bytes = srep.get_field(Tag::SREP).unwrap();

    let mut response = RtMessage::new(5);
    response.add_field(Tag::SIG, sig_bytes).unwrap();
    response.add_field(Tag::PATH, path).unwrap();
    response.add_field(Tag::SREP, srep_bytes).unwrap();
    response.add_field(Tag::CERT, cert_bytes).unwrap();
    response.add_field(Tag::INDX, &index).unwrap();

    response
}

// extract the client's nonce from its request
fn nonce_from_request(buf: &[u8], num_bytes: usize) -> Result<&[u8], Error> {
    if num_bytes < MIN_REQUEST_LENGTH as usize {
        return Err(Error::RequestTooShort);
    }

    let tag_count = &buf[..4];
    let expected_nonc = &buf[8..12];
    let expected_pad = &buf[12..16];

    let tag_count_is_2 = tag_count == [0x02, 0x00, 0x00, 0x00];
    let tag1_is_nonc = expected_nonc == Tag::NONC.wire_value();
    let tag2_is_pad = expected_pad == Tag::PAD.wire_value();

    if tag_count_is_2 && tag1_is_nonc && tag2_is_pad {
        Ok(&buf[0x10..0x50])
    } else {
        Err(Error::InvalidRequest)
    }
}

fn polling_loop(config: &Box<ServerConfig>, online_key: &mut OnlineKey, cert_bytes: &[u8]) {
    let response_counter = AtomicUsize::new(0);
    let keep_running = Arc::new(AtomicBool::new(true));
    let kr = keep_running.clone();

    ctrlc::set_handler(move || kr.store(false, Ordering::Release))
        .expect("failed setting Ctrl-C handler");

    let sock_addr = config.socket_addr().expect("");
    let socket = UdpSocket::bind(&sock_addr).expect("failed to bind to socket");
    let poll_duration = Some(Duration::from_millis(100));

    let mut timer: Timer<()> = Timer::default();
    timer.set_timeout(config.status_interval(), ());

    let mut buf = [0u8; 65_536];
    let mut events = Events::with_capacity(32);
    let mut num_bad_requests = 0u64;

    let poll = Poll::new().unwrap();
    poll.register(&socket, MESSAGE, Ready::readable(), PollOpt::edge())
        .unwrap();
    poll.register(&timer, STATUS, Ready::readable(), PollOpt::edge())
        .unwrap();

    let mut merkle = MerkleTree::new();
    let mut requests = Vec::with_capacity(config.batch_size() as usize);

    macro_rules! check_ctrlc {
        () => {
            if !keep_running.load(Ordering::Acquire) {
                warn!("Ctrl-C caught, exiting...");
                return;
            }
        };
    }

    loop {
        check_ctrlc!();

        poll.poll(&mut events, poll_duration).expect("poll failed");

        for event in events.iter() {
            match event.token() {
                MESSAGE => {
                    let mut done = false;

                    'process_batch: loop {
                        check_ctrlc!();

                        merkle.reset();
                        requests.clear();

                        let resp_start = response_counter.load(Ordering::SeqCst);

                        for i in 0..config.batch_size() {
                            match socket.recv_from(&mut buf) {
                                Ok((num_bytes, src_addr)) => {
                                    if let Ok(nonce) = nonce_from_request(&buf, num_bytes) {
                                        requests.push((Vec::from(nonce), src_addr));
                                        merkle.push_leaf(nonce);
                                    } else {
                                        num_bad_requests += 1;
                                        info!(
                                            "Invalid request ({} bytes) from {} (#{} in batch, resp #{})",
                                            num_bytes, src_addr, i, resp_start + i as usize
                                        );
                                    }
                                }
                                Err(e) => match e.kind() {
                                    ErrorKind::WouldBlock => {
                                        done = true;
                                        break;
                                    }
                                    _ => {
                                        error!(
                                            "Error receiving from socket: {:?}: {:?}",
                                            e.kind(),
                                            e
                                        );
                                        break;
                                    }
                                },
                            };
                        }

                        if requests.is_empty() {
                            break 'process_batch;
                        }

                        let merkle_root = merkle.compute_root();
                        let srep = online_key.make_srep(time::get_time(), &merkle_root);

                        for (i, &(ref nonce, ref src_addr)) in requests.iter().enumerate() {
                            let paths = merkle.get_paths(i);

                            let resp = make_response(&srep, cert_bytes, &paths, i as u32);
                            let resp_bytes = resp.encode().unwrap();

                            let bytes_sent = socket
                                .send_to(&resp_bytes, &src_addr)
                                .expect("send_to failed");
                            let num_responses = response_counter.fetch_add(1, Ordering::SeqCst);

                            info!(
                                "Responded {} bytes to {} for '{}..' (#{} in batch, resp #{})",
                                bytes_sent,
                                src_addr,
                                hex::encode(&nonce[0..4]),
                                i,
                                num_responses
                            );
                        }
                        if done {
                            break 'process_batch;
                        }
                    }
                }

                STATUS => {
                    info!(
                        "responses {}, invalid requests {}",
                        response_counter.load(Ordering::SeqCst),
                        num_bad_requests
                    );

                    timer.set_timeout(config.status_interval(), ());
                }

                _ => unreachable!(),
            }
        }
    }
}

fn kms_support_str() -> &'static str {
    if cfg!(feature = "awskms") {
        " (+AWS KMS)"
    } else if cfg!(feature = "gcpkms") {
        " (+GCP KMS)"
    } else {
        ""
    }
}

pub fn main() {
    use log::Level;

    simple_logger::init_with_level(Level::Info).unwrap();

    info!("Roughenough server v{}{} starting", VERSION, kms_support_str());

    let mut args = env::args();
    if args.len() != 2 {
        error!("Usage: server <ENV|/path/to/config.yaml>");
        process::exit(1);
    }

    let arg1 = args.nth(1).unwrap();
    let config = match config::make_config(&arg1) {
        Err(e) => {
            error!("{:?}", e);
            process::exit(1)
        }
        Ok(ref cfg) if !config::is_valid_config(&cfg) => process::exit(1),
        Ok(cfg) => cfg,
    };

    let mut online_key = OnlineKey::new();
    let public_key: String;

    let cert_bytes = {
        let seed = kms::load_seed(&config).unwrap();
        let mut long_term_key = LongTermKey::new(&seed);
        public_key = hex::encode(long_term_key.public_key());

        long_term_key.make_cert(&online_key).encode().unwrap()
    };

    info!("Long-term public key    : {}", public_key);
    info!("Online public key       : {}", online_key);
    info!("Max response batch size : {}", config.batch_size());
    info!("Status updates every    : {} seconds", config.status_interval().as_secs());
    info!("Server listening on     : {}:{}", config.interface(), config.port());

    polling_loop(&config, &mut online_key, &cert_bytes);

    info!("Done.");
    process::exit(0);
}
