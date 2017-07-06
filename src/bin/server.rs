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
//! ```
//!
//! Where:
//!
//!   * **interface** - IP address or interface name for listening to client requests
//!   * **port** - UDP port to listen to requests
//!   * **seed** - A 32-byte hexadecimal value used as the seed to generate the 
//!                server's long-term key pair. **This is a secret value**, treat it
//!                with care.
//!
//! # Running the Server
//!
//! ```bash
//! $ cargo run --release --bin server /path/to/config.file
//! ```

extern crate byteorder;
extern crate core;
extern crate ring;
extern crate roughenough;
extern crate time;
extern crate untrusted;
extern crate fern;
extern crate ctrlc;
extern crate yaml_rust;
#[macro_use]
extern crate log;

use std::env;
use std::io;
use std::process;
use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use byteorder::{LittleEndian, WriteBytesExt};

use roughenough::{RtMessage, Tag, Error};
use roughenough::{CERTIFICATE_CONTEXT, MIN_REQUEST_LENGTH, SIGNED_RESPONSE_CONTEXT, TREE_LEAF_TWEAK};
use roughenough::hex::*;
use roughenough::sign::Signer;

use ring::{digest, rand};
use ring::rand::SecureRandom;

use yaml_rust::YamlLoader;

const SERVER_VERSION: &'static str = "0.1";

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

fn make_cert(long_term_key: &mut Signer, ephemeral_key: &Signer) -> RtMessage {
    // Make DELE and sign it with long-term key
    let dele_bytes = make_dele_bytes(&ephemeral_key).unwrap();
    let dele_signature = {
        long_term_key.update(CERTIFICATE_CONTEXT.as_bytes());
        long_term_key.update(&dele_bytes);
        long_term_key.sign()
    };

    // Create CERT
    let mut cert_msg = RtMessage::new(2);
    cert_msg.add_field(Tag::SIG, &dele_signature).unwrap();
    cert_msg.add_field(Tag::DELE, &dele_bytes).unwrap();

    cert_msg
}

fn make_response(ephemeral_key: &mut Signer, cert_bytes: &[u8], nonce: &[u8]) -> RtMessage {
    //   create SREP
    //   sign SREP
    //   create response:
    //    - SIG
    //    - PATH (always 0)
    //    - SREP
    //    - CERT (pre-created)
    //    - INDX (always 0)

    let path = [0u8; 0];
    let zeros = [0u8; 4];

    let mut radi: Vec<u8> = Vec::with_capacity(4);
    let mut midp: Vec<u8> = Vec::with_capacity(8);

    // one second (in microseconds)
    radi.write_u32::<LittleEndian>(1000000).unwrap();

    // current epoch time in microseconds
    let now = {
        let tv = time::get_time();
        let secs = (tv.sec as u64) * 1000000;
        let nsecs = (tv.nsec as u64) / 1000;

        secs + nsecs
    };
    midp.write_u64::<LittleEndian>(now).unwrap();

    // Signed response SREP
    let srep_bytes = {
        // hash request nonce
        let mut ctx = digest::Context::new(&digest::SHA512);
        ctx.update(&TREE_LEAF_TWEAK);
        ctx.update(&nonce);
        let digest = ctx.finish();

        let mut srep_msg = RtMessage::new(3);
        srep_msg.add_field(Tag::RADI, &radi).unwrap();
        srep_msg.add_field(Tag::MIDP, &midp).unwrap();
        srep_msg.add_field(Tag::ROOT, digest.as_ref()).unwrap();

        srep_msg.encode().unwrap()
    };

    // signature on SREP
    let srep_signature = {
        ephemeral_key.update(SIGNED_RESPONSE_CONTEXT.as_bytes());
        ephemeral_key.update(&srep_bytes);
        ephemeral_key.sign()
    };

    let mut response = RtMessage::new(5);
    response.add_field(Tag::SIG, &srep_signature).unwrap();
    response.add_field(Tag::PATH, &path).unwrap();
    response.add_field(Tag::SREP, &srep_bytes).unwrap();
    response.add_field(Tag::CERT, cert_bytes).unwrap();
    response.add_field(Tag::INDX, &zeros).unwrap();

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

fn init_logging() {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(
                format_args!("{} [{}] {}", time::now().asctime(), record.level(), message)
            )
        })
        .level(log::LogLevelFilter::Info)
        .chain(std::io::stdout())
        .apply()
        .unwrap();
}

fn load_config(config_file: &str) -> (String, u16, Vec<u8>) {
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

    for (key, value) in cfg[0].as_hash().unwrap() {
        match key.as_str().unwrap() {
            "port" => port = value.as_i64().unwrap() as u16,
            "interface" => iface = value.as_str().unwrap().to_string(),
            "seed" => seed = value.as_str().unwrap().to_string(),
            _ => warn!("ignoring unknown config key '{}'", key.as_str().unwrap())
        }
    }

    let binseed = seed.from_hex()
        .expect("seed value invalid; 'seed' should be 32 byte hex value");

    (iface, port, binseed)
}

fn main() {
    init_logging();

    info!("Roughenough server v{} starting", SERVER_VERSION);

    let mut args = env::args();
    if args.len() != 2 {
        error!("Usage: server /path/to/config.file");
        process::exit(1);
    }

    let (iface, port, seed) = load_config(&args.nth(1).unwrap());

    let mut lt_key = Signer::new(&seed);
    let mut ephemeral_key = create_ephemeral_key();
    let cert_bytes = make_cert(&mut lt_key, &ephemeral_key).encode().unwrap();

    info!("Long-term public key: {}", lt_key.public_key_bytes().to_hex());
    info!("Ephemeral public key: {}", ephemeral_key.public_key_bytes().to_hex());
    info!("Server listening on {}:{}", iface, port);

    let socket = UdpSocket::bind(format!("{}:{}", iface, port)).expect("failed to bind to socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("could not set read timeout");

    let mut buf = [0u8; 65536];
    let mut loop_count = 0u64;
    let mut responses = 0u64;
    let mut bad_requests = 0u64;

    let keep_running = Arc::new(AtomicBool::new(true));
    let kr = keep_running.clone();

    ctrlc::set_handler(move || { kr.store(false, Ordering::Release); })
        .expect("failed setting Ctrl-C handler");

    loop {
        if !keep_running.load(Ordering::Acquire) {
            info!("Ctrl-C caught, exiting...");
            break;
        }

        match socket.recv_from(&mut buf) {
            Ok((num_bytes, src_addr)) => {
                if let Ok(nonce) = nonce_from_request(&buf, num_bytes) {
                    let resp = make_response(&mut ephemeral_key, &cert_bytes, nonce);
                    let resp_bytes = resp.encode().unwrap();

                    socket
                        .send_to(&resp_bytes, src_addr)
                        .expect("could not send response");

                    info!("Responded to {}", src_addr);
                    responses += 1;
                } else {
                    info!("invalid request ({} bytes) from {}", num_bytes, src_addr);
                    bad_requests += 1;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                loop_count += 1;
                if loop_count % 600 == 0 {
                    info!("responses {}, invalid requests {}", responses, bad_requests);
                }
            }
            Err(ref e) => error!("Error {:?}: {:?}", e.kind(), e),
        }
    }

    info!("Done.");
}
