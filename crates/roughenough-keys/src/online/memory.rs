use roughenough_protocol::tags::PublicKey;

use super::aws_lc_ed25519::KeyPair;
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
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};

    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        // Given a MemoryBackend
        let mut backend = MemoryBackend::new(Seed::new_random());

        // When the backend signs something
        let data = b"hello world";
        let signature = backend.sign(data).unwrap();

        // Then that signature validates with aws-lc-rs
        let public_key = backend.public_key();
        let verifier = UnparsedPublicKey::new(&ED25519, public_key.as_array());
        verifier.verify(data, &signature).unwrap();
    }
}
