use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use roughenough_protocol::tags::PublicKey;

use crate::seed::{BackendError, Seed, SeedBackend};

#[derive(Debug, Default)]
pub struct MemoryBackend {
    seed: Option<Seed>,
    public_key: Option<PublicKey>,
}

impl MemoryBackend {
    pub fn new() -> Result<MemoryBackend, BackendError> {
        Ok(Self {
            seed: None,
            public_key: None,
        })
    }

    pub fn from_value(value: &[u8]) -> MemoryBackend {
        let seed = Seed::new(value);
        let mut backend = MemoryBackend::default();
        backend.store_seed(seed).expect("bug: seed is valid");

        backend
    }

    pub fn from_random() -> MemoryBackend {
        let seed = Seed::new_random();
        let mut backend = MemoryBackend::default();
        backend.store_seed(seed).expect("bug: seed is valid");

        backend
    }
}

impl SeedBackend for MemoryBackend {
    fn store_seed(&mut self, seed: Seed) -> Result<(), BackendError> {
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed.expose()).unwrap();
        let public_key = PublicKey::from(keypair.public_key().as_ref());

        self.public_key = Some(public_key);
        self.seed = Some(seed);

        Ok(())
    }

    fn get_seed(&self) -> Result<Seed, BackendError> {
        let seed = self
            .seed
            .as_ref()
            .unwrap_or_else(|| panic!("bug: no seed?"));
        Ok(Seed::new(seed.expose()))
    }

    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError> {
        let signature = {
            let seed = self.get_seed()?;
            let keypair = Ed25519KeyPair::from_seed_unchecked(seed.expose()).unwrap();
            keypair.sign(data)
        };
        Ok(signature.as_ref().try_into().expect("infallible"))
    }

    fn seed_len(&self) -> usize {
        match &self.seed {
            Some(seed) => seed.len(),
            None => 0,
        }
    }

    fn public_key(&self) -> PublicKey {
        *self.public_key.as_ref().unwrap()
    }

    fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key().as_ref().try_into().expect("infallible")
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::ED25519;

    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        // Given a MemoryBackend
        let mut backend = MemoryBackend::new().unwrap();
        let seed = Seed::new_random();
        backend.store_seed(seed).unwrap();

        // When the backend signs something
        let data = b"hello world";
        let signature = backend.sign(data).unwrap();

        // Then that signature validates with aws-lc-rs
        let key_bytes = backend.public_key_bytes();
        let pub_key = aws_lc_rs::signature::UnparsedPublicKey::new(&ED25519, key_bytes);
        pub_key.verify(data, &signature).unwrap();
    }
}
