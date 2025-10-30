use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use roughenough_protocol::tags::PublicKey;

use crate::seed::{BackendError, Secret, SecretBackend};

#[derive(Debug, Default)]
pub struct MemoryBackend {
    secret: Option<Secret>,
    public_key: Option<PublicKey>,
}

impl MemoryBackend {
    pub fn new() -> Result<MemoryBackend, BackendError> {
        Ok(Self {
            secret: None,
            public_key: None,
        })
    }

    pub fn from_value(value: &[u8]) -> MemoryBackend {
        let secret = Secret::new(value);
        let mut backend = MemoryBackend::default();
        backend.store_secret(secret).expect("bug: secret is valid");

        backend
    }

    pub fn from_random() -> MemoryBackend {
        let secret = Secret::new_random();
        let mut backend = MemoryBackend::default();
        backend.store_secret(secret).expect("bug: secret is valid");

        backend
    }
}

impl SecretBackend for MemoryBackend {
    fn store_secret(&mut self, secret: Secret) -> Result<(), BackendError> {
        let keypair = Ed25519KeyPair::from_seed_unchecked(secret.expose()).unwrap();
        let public_key = PublicKey::from(keypair.public_key().as_ref());

        self.public_key = Some(public_key);
        self.secret = Some(secret);

        Ok(())
    }

    fn get_secret(&self) -> Result<Secret, BackendError> {
        let secret = self
            .secret
            .as_ref()
            .unwrap_or_else(|| panic!("bug: no secret?"));
        Ok(Secret::new(secret.expose()))
    }

    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError> {
        let signature = {
            let secret = self.get_secret()?;
            let keypair = Ed25519KeyPair::from_seed_unchecked(secret.expose()).unwrap();
            keypair.sign(data)
        };
        Ok(signature.as_ref().try_into().expect("infallible"))
    }

    fn secret_len(&self) -> usize {
        match &self.secret {
            Some(secret) => secret.len(),
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
        let secret = Secret::new_random();
        backend.store_secret(secret).unwrap();

        // When the backend signs something
        let data = b"hello world";
        let signature = backend.sign(data).unwrap();

        // Then that signature validates with aws-lc-rs
        let key_bytes = backend.public_key_bytes();
        let pub_key = aws_lc_rs::signature::UnparsedPublicKey::new(&ED25519, key_bytes);
        pub_key.verify(data, &signature).unwrap();
    }
}
