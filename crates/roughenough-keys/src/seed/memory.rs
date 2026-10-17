use roughenough_protocol::tags::PublicKey;

use crate::online::aws_lc_ed25519::KeyPair;
use crate::seed::{BackendError, Seed, SeedBackend};

#[derive(Debug)]
pub struct MemoryBackend {
    key_pair: KeyPair,
}

impl MemoryBackend {
    pub fn new(seed: Seed) -> MemoryBackend {
        let key_pair = KeyPair::from_seed(seed.expose());
        MemoryBackend { key_pair }
    }

    pub fn from_value(value: &[u8; 32]) -> MemoryBackend {
        let seed = Seed::from_bytes(value);
        MemoryBackend::new(seed)
    }

    pub fn from_random() -> MemoryBackend {
        let seed = Seed::new_random();
        MemoryBackend::new(seed)
    }
}

impl SeedBackend for MemoryBackend {
    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError> {
        Ok(self.key_pair.sign(data))
    }

    fn public_key(&self) -> PublicKey {
        self.key_pair.public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::assert_backend_signs;

    #[test]
    fn sign_verify_roundtrip() {
        let mut backend = MemoryBackend::new(Seed::new_random());
        assert_backend_signs(&mut backend);
    }
}
