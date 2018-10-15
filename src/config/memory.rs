use config::ServerConfig;
use config::{DEFAULT_BATCH_SIZE, DEFAULT_STATUS_INTERVAL};
use key::KeyProtection;
use std::time::Duration;

use hex;

/// A purely in-memory Roughenough config
/// This is useful for fuzzing a server without the need
/// to create additioanl files.
pub struct MemoryConfig {
    pub port: u16,
    pub interface: String,
    pub seed: Vec<u8>,
    pub batch_size: u8,
    pub status_interval: Duration,
    pub key_protection: KeyProtection,
}

impl MemoryConfig {
    pub fn new(port: u16) -> MemoryConfig {
        MemoryConfig {
            port,
            interface: "127.0.0.1".to_string(),
            seed: hex::decode("a32049da0ffde0ded92ce10a0230d35fe615ec8461c14986baa63fe3b3bac3db")
                .unwrap(),
            batch_size: DEFAULT_BATCH_SIZE,
            status_interval: DEFAULT_STATUS_INTERVAL,
            key_protection: KeyProtection::Plaintext,
        }
    }
}

impl ServerConfig for MemoryConfig {
    fn interface(&self) -> &str {
        self.interface.as_ref()
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn seed(&self) -> Vec<u8> {
        self.seed.clone()
    }

    fn batch_size(&self) -> u8 {
        self.batch_size
    }

    fn status_interval(&self) -> Duration {
        self.status_interval
    }

    fn key_protection(&self) -> &KeyProtection {
        &self.key_protection
    }
}
