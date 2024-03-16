// Copyright 2017-2021 int08h LLC
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
//! The server has multiple ways it can be configured, see
//! [`ServerConfig`](config/trait.ServerConfig.html) for details.
//!

#[macro_use]
extern crate log;

use std::{env, thread};
use std::process;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use log::LevelFilter;
use mio::Events;
use mio::net::UdpSocket;
use once_cell::sync::Lazy;
use simple_logger::SimpleLogger;

use roughenough::config;
use roughenough::config::ServerConfig;
use roughenough::roughenough_version;
use roughenough::server::Server;

// All processing threads poll this. Starts TRUE and will be set to FASLE by
// the Ctrl-C (SIGINT) handler created in `set_ctrlc_handler()`
static KEEP_RUNNING: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(true));

fn polling_loop(cfg: Arc<Mutex<Box<dyn ServerConfig>>>, socket: Arc<UdpSocket>) {
    let mut server = {
        let config = cfg.lock().unwrap();
        let server = Server::new(config.as_ref(), socket);

        display_config(&server, config.as_ref());
        server
    };

    let mut events = Events::with_capacity(2048);

    loop {
        server.process_events(&mut events);

        if !KEEP_RUNNING.load(Ordering::Acquire) {
            warn!("Ctrl-C caught, exiting...");
            return;
        }
    }
}

fn set_ctrlc_handler() {
    ctrlc::set_handler(move || KEEP_RUNNING.store(false, Ordering::Release))
        .expect("failed setting Ctrl-C handler");
}

fn display_config(server: &Server, cfg: &dyn ServerConfig) {
    info!("Processing thread          : {}", server.thread_name());
    info!("Number of workers          : {}", cfg.num_workers());
    info!("Long-term public key       : {}", server.get_public_key());
    info!("Max response batch size    : {}", cfg.batch_size());
    info!("Status updates every       : {} seconds", cfg.status_interval().as_secs());

    info!(
        "Server listening on        : {}:{}",
        cfg.interface(),
        cfg.port()
    );
    if let Some(hc_port) = cfg.health_check_port() {
        info!(
            "TCP health check           : {}:{}",
            cfg.interface(),
            hc_port
        );
    } else {
        info!("TCP health check           : disabled");
    }
    info!(
        "Client req/resp tracking   : {}",
        if cfg.client_stats_enabled() {
            "per-client"
        } else {
            "aggregated"
        }
    );
    if cfg.fault_percentage() > 0 {
        info!("Deliberate response errors : ~{}%", cfg.fault_percentage());
    } else {
        info!("Deliberate response errors : disabled");
    }

}

pub fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .with_utc_timestamps()
        .init()
        .unwrap();

    info!("Roughenough server v{} starting", roughenough_version());

    let mut args = env::args();
    if args.len() != 2 {
        error!("Usage: server <ENV | /path/to/config.yaml>");
        process::exit(1);
    }

    let arg1 = args.nth(1).unwrap();
    let config = match config::make_config(&arg1) {
        Err(e) => {
            error!("{:?}", e);
            process::exit(1)
        }
        Ok(ref cfg) if !config::is_valid_config(cfg.as_ref()) => process::exit(1),
        Ok(cfg) => Arc::new(Mutex::new(cfg)),
    };

    let socket = {
        let sock_addr = config.lock().unwrap().udp_socket_addr().expect("udp sock addr");
        let sock = UdpSocket::bind(&sock_addr).expect("failed to bind to socket");
        Arc::new(sock)
    };

    set_ctrlc_handler();

    // TODO(stuart) move TCP healthcheck out of worker threads as it currently conflicts
    let mut threads = Vec::new();

    for i in 0 .. config.lock().unwrap().num_workers() {
        let cfg = config.clone();
        let sock = socket.try_clone().unwrap();
        let thread = thread::Builder::new()
            .name(format!("worker-{}", i))
            .spawn(move || polling_loop(cfg, sock.into()))
            .expect("failure spawning thread");

        threads.push(thread);
    }

    for t in threads {
        t.join().expect("join failed")
    }

    info!("Done.");
    process::exit(0);
}
