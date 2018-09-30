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
//! Ways to configure the Roughenough server.
//!
//! The [ServerConfig](trait.ServerConfig.html) trait specifies the required and optional
//! parameters available for configuring a Roughenoguh server instance.
//!
//! Implementations of `ServerConfig` obtain configurations from different back-end sources.
//!

extern crate hex;

use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;
use yaml_rust::YamlLoader;
use Error;

const DEFAULT_BATCH_SIZE: u8 = 64;
const DEFAULT_STATUS_INTERVAL: Duration = Duration::from_secs(600);

///
/// Specifies parameters needed to configure a Roughenough server.
///
/// Parameters labeled "**Required**" must are always be provided and have no default value.
/// Parameters labeled "**Optional**" provide default values that can be overridden.
///
/// * **`interface`** - [Required] IP address or interface name for listening to client requests
/// * **`port`** - [Required] UDP port to listen for requests
/// * **`seed`** - [Required] A 32-byte hexadecimal value used to generate the server's long-term
///                key pair. **This is a secret value and must be un-guessable**,
///                treat it with care.
/// * **`batch_size`** - [Optional] The maximum number of requests to process in one batch. All
///                      nonces in a batch are used to build a Merkle tree, the root of which
///                      is signed. Default is 64 requests per batch.
/// * **`status_interval`** - [Optional] Amount of time between each logged status update.
///                           Default is 600 seconds (10 minutes).
///
/// Implementations of this trait obtain a valid configuration from different back-
/// end sources.
///
/// See:
///   * [FileConfig](struct.FileConfig.html)
///
pub trait ServerConfig {
    /// [Required] IP address or interface name to listen for client requests
    fn interface(&self) -> &str;

    /// [Required] UDP port to listen for requests
    fn port(&self) -> u16;

    /// [Required] A 32-byte hexadecimal value used to generate the server's
    /// long-term key pair. **This is a secret value and must be un-guessable**,
    /// treat it with care.
    fn seed(&self) -> &[u8];

    /// [Optional] The maximum number of requests to process in one batch. All
    /// nonces in a batch are used to build a Merkle tree, the root of which is signed.
    /// Default is 64 requests per batch.
    fn batch_size(&self) -> u8;

    /// [Optional] Amount of time between each logged status update.
    /// Default is 600 seconds (10 minutes).
    fn status_interval(&self) -> Duration;

    /// Convenience function to create a `SocketAddr` from the provided `interface` and `port`
    fn socket_addr(&self) -> SocketAddr;
}

///
/// Read the configuration from a YAML file
///
/// Example minimal config file with only the required parameters from
/// [ServerConfig](trait.ServerConfig.html):
///
/// ```yaml
/// interface: 127.0.0.1
/// port: 8686
/// seed: f61075c988feb9cb700a4a6a3291bfbc9cab11b9c9eca8c802468eb38a43d7d3
/// ```
///
pub struct FileConfig {
    port: u16,
    interface: String,
    seed: Vec<u8>,
    batch_size: u8,
    status_interval: Duration,
}

impl FileConfig {
    pub fn from_file(config_file: &str) -> Result<Self, Error> {
        let mut infile = File::open(config_file).expect("failed to open config file");

        let mut contents = String::new();
        infile
            .read_to_string(&mut contents)
            .expect("could not read config file");

        let cfg = YamlLoader::load_from_str(&contents).expect("could not parse config file");

        if cfg.len() != 1 {
            return Err(Error::InvalidConfiguration(
                "Empty or malformed config file".to_string(),
            ));
        }

        let mut config = FileConfig {
            port: 0,
            interface: "unknown".to_string(),
            seed: Vec::new(),
            batch_size: DEFAULT_BATCH_SIZE,
            status_interval: DEFAULT_STATUS_INTERVAL,
        };

        for (key, value) in cfg[0].as_hash().unwrap() {
            match key.as_str().unwrap() {
                "port" => config.port = value.as_i64().unwrap() as u16,
                "interface" => config.interface = value.as_str().unwrap().to_string(),
                "batch_size" => config.batch_size = value.as_i64().unwrap() as u8,
                "seed" => {
                    let val = value.as_str().unwrap().to_string();
                    config.seed = hex::decode(val)
                        .expect("seed value invalid; 'seed' should be 32 byte hex value");
                }
                "status_interval" => {
                    let val = value.as_i64().expect("status_interval value invalid");
                    config.status_interval = Duration::from_secs(val as u64)
                }
                unknown => {
                    return Err(Error::InvalidConfiguration(format!(
                        "unknown config key: {}", unknown
                    )));
                }
            }
        }

        Ok(config)
    }
}

impl ServerConfig for FileConfig {
    fn interface(&self) -> &str {
        self.interface.as_ref()
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn seed(&self) -> &[u8] {
        &self.seed
    }

    fn batch_size(&self) -> u8 {
        self.batch_size
    }

    fn status_interval(&self) -> Duration {
        self.status_interval
    }

    fn socket_addr(&self) -> SocketAddr {
        let addr = format!("{}:{}", self.interface, self.port);
        addr.parse()
            .expect(&format!("could not create socket address from {}", addr))
    }
}
