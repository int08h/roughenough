// Copyright 2017 int08h LLC
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
//! The `roughenough` server is configured via a config file:
//!
//! ```yaml
//! interface: 127.0.0.1
//! port: 8686
//! seed: f61075c988feb9cb700a4a6a3291bfbc9cab11b9c9eca8c802468eb38a43d7d3
//! batch_size: 64
//! ```
//!
//! Where:
//!
//!   * **interface** - IP address or interface name for listening to client requests
//!   * **port** - UDP port to listen to requests
//!   * **seed** - A 32-byte hexadecimal value used as the seed to generate the 
//!                server's long-term key pair. **This is a secret value**, treat it
//!                with care.
//!   * **batch_size** - The number of requests to process in one batch. All nonces
//!                      in a batch are used to build a Merkle tree, the root of which
//!                      is signed.
//!
//! # Running the Server
//!
//! ```bash
//! $ cargo run --release --bin server /path/to/config.file
//! ```

extern crate byteorder;
extern crate ring;
extern crate roughenough;
extern crate time;
extern crate untrusted;
extern crate ctrlc;
extern crate yaml_rust;
#[macro_use]
extern crate log;
extern crate simple_logger;
extern crate mio;
extern crate mio_extras;
extern crate hex;

use std::env;
use std::process;
use std::fs::File;
use std::io::{Read, ErrorKind};
use std::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use mio::{Poll, Token, Ready, PollOpt, Events};
use mio::net::UdpSocket;
use mio_extras::timer::Timer;

use byteorder::{LittleEndian, WriteBytesExt};

use roughenough::{RtMessage, Tag, Error};
use roughenough::{VERSION, CERTIFICATE_CONTEXT, MIN_REQUEST_LENGTH, SIGNED_RESPONSE_CONTEXT};
use roughenough::sign::Signer;
use roughenough::merkle::*;

use ring::rand;
use ring::rand::SecureRandom;

use yaml_rust::YamlLoader;

const MESSAGE: Token = Token(0);
const STATUS: Token = Token(1);

pub static NUM_RESPONSES: AtomicUsize = AtomicUsize::new(0);

fn create_ephemeral_key() -> Signer {
    let rng = rand::SystemRandom::new();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed).unwrap();

    Signer::new(&seed)
}

fn make_dele_bytes(ephemeral_key: &Signer) -> Result<Vec<u8>, Error> {
    let zeros = [0u8; 8];
    let max = [0xff; 8];

    let mut dele_msg = RtMessage::new(3);
    dele_msg.add_field(Tag::PUBK, ephemeral_key.public_key_bytes())?;
    dele_msg.add_field(Tag::MINT, &zeros)?;
    dele_msg.add_field(Tag::MAXT, &max)?;

    dele_msg.encode()
}

fn make_key_and_cert(seed: &[u8]) -> (Signer, Vec<u8>) {
    let mut long_term_key = Signer::new(seed);
    let ephemeral_key = create_ephemeral_key();

    info!("Long-term public key: {}", hex::encode(long_term_key.public_key_bytes()));
    info!("Ephemeral public key: {}", hex::encode(ephemeral_key.public_key_bytes()));

    // Make DELE and sign it with long-term key
    let dele_bytes = make_dele_bytes(&ephemeral_key).unwrap();
    let dele_signature = {
        long_term_key.update(CERTIFICATE_CONTEXT.as_bytes());
        long_term_key.update(&dele_bytes);
        long_term_key.sign()
    };

    // Create CERT
    let cert_bytes = {
        let mut cert_msg = RtMessage::new(2);
        cert_msg.add_field(Tag::SIG, &dele_signature).unwrap();
        cert_msg.add_field(Tag::DELE, &dele_bytes).unwrap();

        cert_msg.encode().unwrap()
    };

    (ephemeral_key, cert_bytes)
}

struct SRep {
    raw_bytes: Vec<u8>,
    signature: Vec<u8>
}

fn make_srep(ephemeral_key: &mut Signer, root: &[u8]) -> SRep {
    //   create SREP
    //   sign SREP
    //   create response:
    //    - SIG
    //    - PATH (always 0)
    //    - SREP
    //    - CERT (pre-created)
    //    - INDX (always 0)

    
    let mut radi = [0; 4];
    let mut midp = [0; 8];

    
    // one second (in microseconds)
    (&mut radi as &mut [u8]).write_u32::<LittleEndian>(1_000_000).unwrap();

    // current epoch time in microseconds
    let now = {
        let tv = time::get_time();
        let secs = (tv.sec as u64) * 1_000_000;
        let nsecs = (tv.nsec as u64) / 1_000;

        secs + nsecs
    };
    (&mut midp as &mut [u8]).write_u64::<LittleEndian>(now).unwrap();

    // Signed response SREP
    let srep_bytes = {
        let mut srep_msg = RtMessage::new(3);
        srep_msg.add_field(Tag::RADI, &radi).unwrap();
        srep_msg.add_field(Tag::MIDP, &midp).unwrap();
        srep_msg.add_field(Tag::ROOT, root).unwrap();

        srep_msg.encode().unwrap()
    };

    // signature on SREP
    let srep_signature = {
        ephemeral_key.update(SIGNED_RESPONSE_CONTEXT.as_bytes());
        ephemeral_key.update(&srep_bytes);
        ephemeral_key.sign()
    };

    SRep {
        raw_bytes: srep_bytes,
        signature: srep_signature
    }
}

fn make_response(srep: &SRep, cert_bytes: &[u8], path: &[u8], idx: u32) -> RtMessage {

    let mut index = [0; 4];
    (&mut index as &mut [u8]).write_u32::<LittleEndian>(idx).unwrap();


    let mut response = RtMessage::new(5);
    response.add_field(Tag::SIG, &srep.signature).unwrap();
    response.add_field(Tag::PATH, &path).unwrap();
    response.add_field(Tag::SREP, &srep.raw_bytes).unwrap();
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

fn load_config(config_file: &str) -> (SocketAddr, Vec<u8>, u8) {
    let mut infile = File::open(config_file)
        .expect("failed to open config file");

    let mut contents = String::new();
    infile.read_to_string(&mut contents)
        .expect("could not read config file");

    let cfg = YamlLoader::load_from_str(&contents)
        .expect("could not parse config file");

    if cfg.len() != 1 {
        panic!("empty or malformed config file");
    }

    let mut port: u16 = 0;
    let mut iface: String = "unknown".to_string();
    let mut seed: String = "".to_string();
    let mut batch_size: u8 = 1;

    for (key, value) in cfg[0].as_hash().unwrap() {
        match key.as_str().unwrap() {
            "port" => port = value.as_i64().unwrap() as u16,
            "interface" => iface = value.as_str().unwrap().to_string(),
            "seed" => seed = value.as_str().unwrap().to_string(),
            "batch_size" => batch_size = value.as_i64().unwrap() as u8,
            _ => warn!("ignoring unknown config key '{}'", key.as_str().unwrap())
        }
    }

    let addr = format!("{}:{}", iface, port);
    let sock_addr: SocketAddr = addr.parse()
        .expect(&format!("could not create socket address from {}", addr));

    let binseed = hex::decode(seed)
        .expect("seed value invalid; 'seed' should be 32 byte hex value");

    (sock_addr, binseed, batch_size)
}

fn polling_loop(addr: &SocketAddr, mut ephemeral_key: &mut Signer, cert_bytes: &[u8], batch_size: u8) {
    let keep_running = Arc::new(AtomicBool::new(true));
    let kr = keep_running.clone();

    ctrlc::set_handler(move || kr.store(false, Ordering::Release))
        .expect("failed setting Ctrl-C handler");

    let socket = UdpSocket::bind(addr).expect("failed to bind to socket");
    let status_duration = Duration::from_secs(6);
    let poll_duration = Some(Duration::from_millis(100));

    let mut timer: Timer<()> = Timer::default();
    timer.set_timeout(status_duration, ());

    
    let mut buf = [0u8; 65_536];
    let mut events = Events::with_capacity(32);
    let mut num_bad_requests = 0u64;

    let poll = Poll::new().unwrap();
    poll.register(&socket, MESSAGE, Ready::readable(), PollOpt::edge()).unwrap();
    poll.register(&timer, STATUS, Ready::readable(), PollOpt::edge()).unwrap();

    let mut merkle = MerkleTree::new();
    let mut requests = Vec::with_capacity(batch_size as usize);

    macro_rules! check_ctrlc {
        () => {
            if !keep_running.load(Ordering::Acquire) {
                warn!("Ctrl-C caught, exiting...");
                return;
            }
        }
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

                        let resp_start = NUM_RESPONSES.load(Ordering::SeqCst);

                        for i in 0..batch_size {
                            match socket.recv_from(&mut buf) {
                                Ok((num_bytes, src_addr)) => {
                                    if let Ok(nonce) = nonce_from_request(&buf, num_bytes) {
                                        requests.push((Vec::from(nonce), src_addr));
                                        merkle.push_leaf(nonce);
                                    } else {
                                        num_bad_requests += 1;
                                        info!("Invalid request ({} bytes) from {} (#{} in batch, resp #{})", num_bytes, src_addr, i, resp_start + i as usize);
                                    }
                                },
                                Err(e) => match e.kind() {
                                    ErrorKind::WouldBlock => {
                                        done = true;
                                        break;
                                    },
                                    _ => panic!("recv_from failed with {:?}", e)
                                }
                            };
                        }

                        if requests.is_empty() {
                            break 'process_batch
                        }

                        let root = merkle.compute_root();
                        let srep = make_srep(&mut ephemeral_key, &root);

                        for (i, &(ref nonce, ref src_addr)) in requests.iter().enumerate() {
                            let paths: Vec<_> = merkle.get_paths(i).into_iter().flat_map(|x| x).collect();

                            let resp = make_response(&srep, cert_bytes, &paths, i as u32);
                            let resp_bytes = resp.encode().unwrap();

                            let bytes_sent = socket.send_to(&resp_bytes, &src_addr).expect("send_to failed");
                            let num_responses = NUM_RESPONSES.fetch_add(1, Ordering::SeqCst);

                            info!("Responded {} bytes to {} for '{}..' (#{} in batch, resp #{})", bytes_sent, src_addr, hex::encode(&nonce[0..4]), i, num_responses);
                        }
                        if done {
                            break 'process_batch
                        }
                    }
                    
                }

                STATUS => {
                    info!("responses {}, invalid requests {}", NUM_RESPONSES.load(Ordering::SeqCst), num_bad_requests);
                    timer.set_timeout(status_duration, ());
                }

                _ => unreachable!()
            }
        }
    }
}

pub fn main() {
    use log::Level;

    simple_logger::init_with_level(Level::Info).unwrap();

    info!("Roughenough server v{} starting", VERSION);

    let mut args = env::args();
    if args.len() != 2 {
        error!("Usage: server /path/to/config.file");
        process::exit(1);
    }

    let (addr, key_seed, batch_size) = load_config(&args.nth(1).unwrap());
    let (mut ephemeral_key, cert_bytes) = make_key_and_cert(&key_seed);

    info!("Server listening on {}", addr);

    if env::var("BENCH").is_ok()  {
        log::set_max_level(log::LevelFilter::Warn);

        thread::spawn(|| {
            loop {
                let old = time::get_time().sec;
                let old_reqs = NUM_RESPONSES.load(Ordering::SeqCst);

                thread::sleep(Duration::from_secs(1));

                let new = time::get_time().sec;
                let new_reqs = NUM_RESPONSES.load(Ordering::SeqCst);

                warn!("Processing at {:?} reqs/sec", (new_reqs - old_reqs) / (new - old) as usize);
            }
        });
    }


    polling_loop(&addr, &mut ephemeral_key, &cert_bytes, batch_size);

    info!("Done.");
    process::exit(0);
}
