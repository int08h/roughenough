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

use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{env, io, thread};
use std::path::Path;
use std::time::Duration;
use log::LevelFilter;
use mio::net::UdpSocket;
use mio::Events;
use net2::unix::UnixUdpBuilderExt;
use net2::UdpBuilder;
use once_cell::sync::Lazy;
use simple_logger::SimpleLogger;

use roughenough::config;
use roughenough::config::ServerConfig;
use roughenough::roughenough_version;
use roughenough::server::Server;
use roughenough::stats::{Reporter, StatsQueue};

// All processing threads poll this. Starts TRUE and will be set to FASLE by
// the Ctrl-C (SIGINT) handler created in `set_ctrlc_handler()`
static KEEP_RUNNING: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(true));

fn polling_loop(cfg: Arc<Mutex<Box<dyn ServerConfig>>>, socket: UdpSocket, queue: Arc<StatsQueue>) {
    let mut server = {
        let config = cfg.lock().unwrap();
        let server = Server::new(config.as_ref(), socket, queue);

        display_config(&server, config.as_ref());
        server
    };

    let mut events = Events::with_capacity(1024);

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

// Bind to the server port using SO_REUSEPORT and SO_REUSEADDR so the kernel will more fairly
// balance traffic to each worker. https://lwn.net/Articles/542629/
fn bind_socket(config: Arc<Mutex<Box<dyn ServerConfig>>>) -> io::Result<UdpSocket> {
    let sock_addr = config
        .lock()
        .unwrap()
        .udp_socket_addr()
        .expect("udp sock addr");

    let std_socket = UdpBuilder::new_v4()?
        .reuse_address(true)?
        .reuse_port(true)?
        .bind(sock_addr)?;

    let mio_socket: UdpSocket = UdpSocket::from_socket(std_socket)?;
    Ok(mio_socket)
}

fn display_config(server: &Server, cfg: &dyn ServerConfig) {
    info!("Processing thread          : {}", server.thread_name());
    info!("Number of workers          : {}", cfg.num_workers());
    info!("Long-term public key       : {}", server.get_public_key());
    info!("Max response batch size    : {}", cfg.batch_size());
    info!(
        "Status updates every       : {} seconds",
        cfg.status_interval().as_secs()
    );

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
    if cfg.client_stats_enabled() && cfg.persistence_directory().is_some() {
        info!("Persistence directory      : {}", cfg.persistence_directory().unwrap().display());
    }
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

    set_ctrlc_handler();

    // TODO(stuart) TCP healthcheck REUSEADDR and RESUSEPORT on the tcp socket

    let num_workers = config.lock().unwrap().num_workers();
    let stats_queue = Arc::new(StatsQueue::new(num_workers * 2));
    let mut threads = Vec::new();

    for i in 0..num_workers {
        let queue = stats_queue.clone();
        let cfg = config.clone();
        let socket = bind_socket(cfg.clone()).unwrap();
        let thread = thread::Builder::new()
            .name(format!("worker-{}", i))
            .spawn(move || polling_loop(cfg, socket, queue))
            .expect("failure spawning thread");

        threads.push(thread);
    }

    let mut reporter = Reporter::new(stats_queue.clone(), &Duration::from_secs(10), Path::new("/tmp"));

    let report_thread = thread::Builder::new()
        .name("stats-reporting".to_string())
        .spawn(move || { reporter.processing_loop() })
        .expect("failure spawning thread");

    threads.push(report_thread);

    for t in threads {
        t.join().expect("join failed")
    }

    info!("Done.");
    process::exit(0);
}
