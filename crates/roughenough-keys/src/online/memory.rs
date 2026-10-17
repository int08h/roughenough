use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use roughenough_protocol::tags::PublicKey;

use crate::seed::{BackendError, Seed, SeedBackend};

#[derive(Debug)]
pub struct MemoryBackend {
    seed: Seed,
    public_key: PublicKey,
}

impl MemoryBackend {
    pub fn new(seed: Seed) -> MemoryBackend {
        let public_key = PublicKey::try_from(keypair(&seed).public_key().as_ref())
            .expect("Ed25519 public keys are 32 bytes");

        MemoryBackend { seed, public_key }
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

fn keypair(seed: &Seed) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(seed.expose()).expect("any 32-byte seed is valid")
}

impl SeedBackend for MemoryBackend {
    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError> {
        let signature = keypair(&self.seed).sign(data);
        Ok(signature.as_ref().try_into().expect("infallible"))
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
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
