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
extern crate log;

use std::net::SocketAddr;
use std::time::Duration;

mod file;

pub use self::file::FileConfig;

mod environment;

pub use self::environment::EnvironmentConfig;

use key;
use Error;
use KeyProtection;

/// Maximum number of requests to process in one batch and include the the Merkle tree.
pub const DEFAULT_BATCH_SIZE: u8 = 64;

/// Amount of time between each logged status update.
pub const DEFAULT_STATUS_INTERVAL: Duration = Duration::from_secs(600);

///
/// Specifies parameters needed to configure a Roughenough server.
///
/// Parameters labeled "**Required**" must always be provided and have no default value
/// while those labeled "**Optional**" provide default values that can be overridden.
///
/// YAML Key | Environment Variable | Necessity | Description
/// --- | --- | --- | ---
/// `interface` | `ROUGHENOUGH_INTERFACE` | Required | IP address or interface name for listening to client requests
/// `port` | `ROUGHENOUGH_PORT` | Required | UDP port to listen for requests
/// `seed` | `ROUGHENOUGH_SEED` | Required | A 32-byte hexadecimal value used to generate the server's long-term key pair. **This is a secret value and must be un-guessable**, treat it with care.
/// `batch_size` | `ROUGHENOUGH_BATCH_SIZE` | Optional | The maximum number of requests to process in one batch. All nonces in a batch are used to build a Merkle tree, the root of which is signed. Defaults to [DEFAULT_BATCH_SIZE](constant.DEFAULT_BATCH_SIZE.html) requests per batch.
/// `status_interval` | `ROUGHENOUGH_STATUS_INTERVAL` | Optional | Number of _seconds_ between each logged status update. Default value is [DEFAULT_STATUS_INTERVAL](constant.DEFAULT_STATUS_INTERVAL.html).
///
/// Implementations of this trait obtain a valid configuration from different back-end
/// sources. See:
///   * [FileConfig](struct.FileConfig.html) - configure via a YAML file
///   * [EnvironmentConfig](struct.EnvironmentConfig.html) - configure via environment vars
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
    /// Defaults to [DEFAULT_BATCH_SIZE](constant.DEFAULT_BATCH_SIZE.html)
    fn batch_size(&self) -> u8;

    /// [Optional] Amount of time between each logged status update.
    /// Defaults to [DEFAULT_STATUS_INTERVAL](constant.DEFAULT_STATUS_INTERVAL.html)
    fn status_interval(&self) -> Duration;

    /// Convenience function to create a `SocketAddr` from the provided `interface` and `port`
    fn socket_addr(&self) -> Result<SocketAddr, Error>;

    /// Method used to protect the long-term key pair.
    fn key_protection(&self) -> KeyProtection;
}

///
/// Factory function to create a `ServerConfig` trait object based on the provided `arg`
///
pub fn make_config(arg: &str) -> Result<Box<ServerConfig>, Error> {
    if arg == "ENV" {
        match EnvironmentConfig::new() {
            Ok(cfg) => Ok(Box::new(cfg)),
            Err(e) => Err(e),
        }
    } else {
        match FileConfig::new(arg) {
            Ok(cfg) => Ok(Box::new(cfg)),
            Err(e) => Err(e),
        }
    }
}

///
/// Validate configuration settings
///
pub fn is_valid_config(cfg: &Box<ServerConfig>) -> bool {
    let mut is_valid = true;

    if cfg.port() == 0 {
        error!("unset port: {}", cfg.port());
        is_valid = false;
    }
    if cfg.interface().is_empty() {
        error!("interface is missing");
        is_valid = false;
    }
    if cfg.seed().is_empty() {
        error!("seed value is missing");
        is_valid = false;
    }
    if !cfg.seed().is_empty() && cfg.seed().len() != 32 {
        error!("seed value must be 32 characters long");
        is_valid = false;
    }
    if cfg.batch_size() < 1 || cfg.batch_size() > 64 {
        error!(
            "batch_size {} is invalid; valid range 1-64",
            cfg.batch_size()
        );
        is_valid = false;
    }

    if is_valid {
        match cfg.socket_addr() {
            Err(e) => {
                error!(
                    "failed to create socket {}:{} {:?}",
                    cfg.interface(),
                    cfg.port(),
                    e
                );
                is_valid = false;
            }
            _ => (),
        }
    }

    is_valid
}
