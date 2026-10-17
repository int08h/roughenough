use std::time::Duration;

use roughenough_common::clocksource::ClockSource;
use roughenough_protocol::ToWire;
use roughenough_protocol::tags::{Certificate, Delegation, ProtocolVersion, PublicKey, Signature};

use crate::online::aws_lc_ed25519::KeyPair;
use crate::online::onlinekey::OnlineKey;
use crate::seed::SeedBackend;

/// The server's long-term Ed25519 identity.
pub struct LongTermIdentity {
    backend: Box<dyn SeedBackend>,
}

impl LongTermIdentity {
    pub fn new(backend: Box<dyn SeedBackend>) -> LongTermIdentity {
        LongTermIdentity { backend }
    }

    /// Retrieves the raw public key bytes associated with this LongTermIdentity.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.backend.public_key().as_array()
    }

    /// Retrieves the public key associated with this LongTermIdentity.
    pub fn public_key(&self) -> PublicKey {
        self.backend.public_key()
    }

    /// Creates a new [`OnlineKey`] and delegation certificate (CERT) signed by the long-term key.
    /// The new [`OnlineKey`] shares the [`ClockSource`] provided. The delegation is valid from the
    /// current `now` time to `now + validity_length` in the future.
    ///
    /// # Arguments
    ///
    /// * `clock` - Clock source for determining certificate validity timestamps. The returned
    ///   [`OnlineKey`] will use this clock source.
    /// * `validity_length` - Length of time the generated [`OnlineKey`] will be valid.
    ///
    pub fn make_online_key(&mut self, clock: &ClockSource, validity_length: Duration) -> OnlineKey {
        let key_pair = KeyPair::generate();
        let dele = Delegation::new(
            key_pair.public_key(),
            clock.epoch_seconds(),
            validity_length,
        );

        let dele_prefix = ProtocolVersion::RFC.dele_prefix();
        let mut to_sign = dele_prefix.to_vec();
        to_sign.extend_from_slice(&dele.as_bytes().expect("DELE serialization should not fail"));

        let dele_sig: [u8; 64] = self
            .backend
            .sign(&to_sign)
            .expect("should not fail; can't continue if it does");
        let sig = Signature::from(dele_sig);
        let cert = Certificate::new(sig, dele);

        OnlineKey::new(key_pair, cert, clock.clone())
    }
}
