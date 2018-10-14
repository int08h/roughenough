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
use std::net::SocketAddr;

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
use roughenough::server::Server;



macro_rules! check_ctrlc {
    ($keep_running:expr) => {
        if !$keep_running.load(Ordering::Acquire) {
            warn!("Ctrl-C caught, exiting...");
            return;
        }
    }
}





fn polling_loop(config: Box<ServerConfig>) {
    let mut server = Server::new(config);

    info!("Long-term public key    : {}", server.get_public_key());
    info!("Online public key       : {}", server.get_online_key());
    info!("Max response batch size : {}", server.get_config().batch_size());
    info!("Status updates every    : {} seconds", server.get_config().status_interval().as_secs());
    info!("Server listening on     : {}:{}", server.get_config().interface(), server.get_config().port());


    let kr = server.get_keep_running();
    let kr_new = kr.clone();

    ctrlc::set_handler(move || kr.store(false, Ordering::Release))
        .expect("failed setting Ctrl-C handler");


    loop {
        check_ctrlc!(kr_new);
        if server.process_events() {
            return;
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

    polling_loop(config);

    info!("Done.");
    process::exit(0);
}
