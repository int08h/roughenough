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

use std::env;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::LevelFilter;
use mio::Events;
use simple_logger::SimpleLogger;

use roughenough::config;
use roughenough::config::ServerConfig;
use roughenough::roughenough_version;
use roughenough::server::Server;

fn polling_loop(config: Box<dyn ServerConfig>) {
    let mut server = Server::new(config.as_ref());
    let keep_running = Arc::new(AtomicBool::new(true));

    display_config(&server, config.as_ref());

    let kr_clone = keep_running.clone();
    ctrlc::set_handler(move || kr_clone.store(false, Ordering::Release))
        .expect("failed setting Ctrl-C handler");

    let mut events = Events::with_capacity(1024);

    loop {
        server.process_events(&mut events);

        if !keep_running.load(Ordering::Acquire) {
            warn!("Ctrl-C caught, exiting...");
            return;
        }
    }
}

fn display_config(server: &Server, cfg: &dyn ServerConfig) {
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
        Ok(cfg) => cfg,
    };

    polling_loop(config);

    info!("Done.");
    process::exit(0);
}
