use std::fmt::{Debug, Display, Formatter};

use clap::ValueEnum;
#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
use linux_keyutils::KeyError;
use roughenough_protocol::tags::PublicKey;
use zeroize::Zeroize;

#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
mod linuxkrs;
mod memory;
#[cfg(feature = "online-pkcs11")]
mod pkcs11;
#[cfg(feature = "online-ssh-agent")]
mod sshagent;

#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
pub use linuxkrs::LinuxKrsBackend;
pub use memory::MemoryBackend;
#[cfg(feature = "online-pkcs11")]
pub use pkcs11::{PKCS11_LIBRARY_ENV, PKCS11_PIN_ENV, PKCS11_SLOT_ENV, Pkcs11Backend};
#[cfg(feature = "online-ssh-agent")]
pub use sshagent::SshAgentBackend;

/// Seed backends keep the seed/long-term key available for on-line use while protecting it from
/// unauthorized access. A backend receives its seed when it is constructed and never hands it
/// back.
pub trait SeedBackend: Send {
    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError>;
    fn public_key(&self) -> PublicKey;
}

/// The seed backends a build can offer; [`open`] reports the ones compiled out.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    #[value(name = "memory")]
    Memory,
    #[value(name = "krs")]
    Krs,
    #[value(name = "ssh-agent", alias = "sshagent")]
    SshAgent,
    #[value(name = "pkcs11")]
    Pkcs11,
}

impl BackendKind {
    /// Backends that keep a key on a device generate it there and take no seed
    pub fn takes_seed(self) -> bool {
        !matches!(self, BackendKind::Pkcs11)
    }

    fn feature(self) -> &'static str {
        match self {
            // Always compiled in, so `open` never reports it unavailable
            BackendKind::Memory => "none",
            BackendKind::Krs => "online-linux-krs (Linux only)",
            BackendKind::SshAgent => "online-ssh-agent",
            BackendKind::Pkcs11 => "online-pkcs11",
        }
    }
}

impl Display for BackendKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = self
            .to_possible_value()
            .expect("no BackendKind variant is skipped");
        f.write_str(value.get_name())
    }
}

/// Construct the `kind` backend holding `seed`. Backends that keep their key on a device take
/// `None` (see [`BackendKind::takes_seed`]); the others require `Some`.
pub fn open(kind: BackendKind, seed: Option<Seed>) -> Result<Box<dyn SeedBackend>, BackendError> {
    match (kind, seed) {
        (BackendKind::Memory, Some(seed)) => Ok(Box::new(MemoryBackend::new(seed))),
        #[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
        (BackendKind::Krs, Some(seed)) => Ok(Box::new(LinuxKrsBackend::new(seed)?)),
        #[cfg(feature = "online-ssh-agent")]
        (BackendKind::SshAgent, Some(seed)) => Ok(Box::new(SshAgentBackend::new(seed)?)),
        #[cfg(feature = "online-pkcs11")]
        (BackendKind::Pkcs11, None) => Ok(Box::new(Pkcs11Backend::from_env()?)),
        (kind, seed) if kind.takes_seed() != seed.is_some() => {
            Err(BackendError::SeedMismatch(kind))
        }
        (kind, _) => Err(BackendError::BackendNotAvailable(kind, kind.feature())),
    }
}

/// Secret value used to derive the keypair of a LongTermIdentity.
///
/// The bytes live on the heap so that moving a `Seed` copies only a pointer and leaves no seed
/// bytes behind on the stack.
pub struct Seed(Box<[u8; 32]>);

#[derive(thiserror::Error, Debug)]
#[error("seed must be 32 bytes, found {0}")]
pub struct InvalidSeedLength(pub usize);

impl Seed {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: &[u8; 32]) -> Seed {
        // Allocate zeroed then copy, so no stack temporary holds the seed
        let mut boxed = Box::new([0u8; 32]);
        boxed.copy_from_slice(bytes);
        Seed(boxed)
    }

    pub fn new_random() -> Seed {
        let mut boxed = Box::new([0u8; 32]);
        aws_lc_rs::rand::fill(boxed.as_mut()).expect("should be infallible");
        Seed(boxed)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Seed {
    type Error = InvalidSeedLength;

    fn try_from(bytes: &[u8]) -> Result<Seed, InvalidSeedLength> {
        let bytes: &[u8; 32] = bytes
            .try_into()
            .map_err(|_| InvalidSeedLength(bytes.len()))?;
        Ok(Seed::from_bytes(bytes))
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Debug for Seed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Seed(len={})", Self::LEN)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("'{0}' not found")]
    NotFound(String),

    #[error("'{0}'")]
    NotSupported(String),

    #[error("Seed backend '{0}' is not available (requires compile-time feature {1})")]
    BackendNotAvailable(BackendKind, &'static str),

    #[error("Seed backend '{0}' {expects}", expects = if .0.takes_seed() { "requires a seed" } else { "does not take a seed" })]
    SeedMismatch(BackendKind),

    #[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
    #[error("{0}")]
    Krs(#[from] KeyError),

    #[cfg(feature = "online-ssh-agent")]
    #[error("{0}")]
    SshAgent(#[from] ssh_agent_client_rs::Error),

    #[cfg(feature = "online-pkcs11")]
    #[error("{0}")]
    Pkcs11(#[from] cryptoki::error::Error),

    #[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
    #[error("KRS worker thread disconnected unexpectedly")]
    WorkerDisconnect,
}

// In the future, take a look at memfd_secret  https://man.archlinux.org/man/memfd_secret.2.en
// Downside is no glibc call for it, and only available in kernel 6.5+

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::assert_backend_signs;

    #[test]
    fn invalid_seed_length_is_an_error() {
        assert!(Seed::try_from(&b"this won't work"[..]).is_err());
    }

    #[test]
    fn seed_try_from_accepts_32_bytes_only() {
        for len in [31, 33] {
            match Seed::try_from(vec![7u8; len].as_slice()) {
                Err(InvalidSeedLength(found)) => assert_eq!(found, len),
                Ok(_) => panic!("{len}-byte seed was accepted"),
            }
        }

        let seed = Seed::try_from([7u8; 32].as_slice()).unwrap();
        assert_eq!(seed.expose(), &[7u8; 32]);
    }

    #[test]
    fn seed_debug_does_not_print_bytes() {
        let debug = format!("{:?}", Seed::from_bytes(&[0xab; 32]));
        assert!(!debug.contains("ab"), "{debug}");
        assert!(!debug.contains("171"), "{debug}");
    }

    #[test]
    fn open_memory_requires_seed() {
        match open(BackendKind::Memory, None) {
            Err(BackendError::SeedMismatch(BackendKind::Memory)) => {}
            Ok(_) => panic!("memory backend opened without a seed"),
            Err(other) => panic!("expected SeedMismatch, got {other:?}"),
        }
    }

    #[test]
    fn open_memory_signs() {
        let mut backend = open(BackendKind::Memory, Some(Seed::new_random())).unwrap();
        assert_backend_signs(backend.as_mut());
    }

    #[cfg(not(feature = "online-pkcs11"))]
    #[test]
    fn open_pkcs11_without_feature_is_not_available() {
        match open(BackendKind::Pkcs11, None) {
            Err(BackendError::BackendNotAvailable(BackendKind::Pkcs11, feature)) => {
                assert_eq!(feature, "online-pkcs11");
            }
            Ok(_) => panic!("expected BackendNotAvailable, got Ok"),
            Err(other) => panic!("expected BackendNotAvailable, got {other:?}"),
        }
    }

    #[cfg(feature = "online-pkcs11")]
    #[test]
    fn open_pkcs11_with_feature_is_available() {
        // Without a configured token or library construction fails, but never as unavailable
        if let Err(BackendError::BackendNotAvailable(kind, feature)) =
            open(BackendKind::Pkcs11, None)
        {
            panic!("{kind} unavailable with its feature enabled: {feature}");
        }
    }

    #[test]
    fn open_pkcs11_with_seed_is_rejected() {
        match open(BackendKind::Pkcs11, Some(Seed::new_random())) {
            Err(e @ BackendError::SeedMismatch(BackendKind::Pkcs11)) => {
                assert_eq!(e.to_string(), "Seed backend 'pkcs11' does not take a seed");
            }
            Ok(_) => panic!("pkcs11 backend accepted a seed"),
            Err(other) => panic!("expected SeedMismatch, got {other:?}"),
        }
    }

    #[test]
    fn backend_kind_parses_names() {
        for (name, kind) in [
            ("memory", BackendKind::Memory),
            ("krs", BackendKind::Krs),
            ("ssh-agent", BackendKind::SshAgent),
            ("sshagent", BackendKind::SshAgent),
            ("pkcs11", BackendKind::Pkcs11),
        ] {
            assert_eq!(BackendKind::from_str(name, true), Ok(kind), "{name}");
        }
        assert!(BackendKind::from_str("tpm", true).is_err());
        assert_eq!(BackendKind::SshAgent.to_string(), "ssh-agent");
    }
}
