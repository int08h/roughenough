use std::any::Any;
use std::fmt::{Debug, Formatter};

#[cfg(feature = "pq")]
use pqcrypto_falcon::{falconpadded512, falconpadded512_keypair};
#[cfg(feature = "pq")]
use pqcrypto_traits::sign::{PublicKey as FalconPublicKey, SecretKey as FalconSecretKey};

#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
use linux_keyutils::KeyError;
use roughenough_common::crypto::random_bytes;
use roughenough_protocol::tags::PublicKey;
use zeroize::ZeroizeOnDrop;

#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
pub use crate::online::linuxkrs::*;
pub use crate::online::memory::*;
#[cfg(feature = "online-ssh-agent")]
pub use crate::online::sshagent::*;

/// Seed backends keep the seed/long-term key available for on-line use while protecting it from
/// unauthorized access.
#[allow(clippy::len_without_is_empty)]
pub trait SeedBackend {
    fn store_seed(&mut self, seed: Seed) -> Result<(), BackendError>;
    fn get_seed(&self) -> Result<Seed, BackendError>;
    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError>;
    fn seed_len(&self) -> usize;
    fn public_key(&self) -> PublicKey;
    fn public_key_bytes(&self) -> [u8; 32];
}

const ED25519_SEED_LEN: usize = 32;
const FALCON512_SEED_LEN: usize = falconpadded512::public_key_bytes() + falconpadded512::secret_key_bytes();

/// Secret value used either as the secret key or to derive a key/keypair of a LongTermIdentity.
#[derive(ZeroizeOnDrop)]
pub enum Seed {
    Ed25519 { seed: Vec<u8> },
    Falcon512 { pk: Vec<u8>, sk: Vec<u8> },
}

#[allow(clippy::len_without_is_empty)]
impl Seed {
    pub fn new_ed25519(value: &[u8]) -> Self {
        assert_eq!(value.len(), ED25519_SEED_LEN, "value must be 32 bytes");
        Self::Ed25519 { seed: Vec::from(value) }
    }

    pub fn new_falcon512(value: &[u8]) -> Self {
        assert_eq!(value.len(), FALCON512_SEED_LEN, "wrong length for falcon512 seed");
        Self::Falcon512 {
            pk: Vec::from(&value[..falconpadded512::public_key_bytes()]),
            sk: Vec::from(&value[falconpadded512::public_key_bytes()..]),
        }
    }

    pub fn new_random_ed15519() -> Self {
        Self::Ed25519 { seed: random_bytes::<32>().to_vec() }
    }

    #[cfg(feature = "pq")]
    pub fn new_random_falcon512() -> Self {
        let (pk, sk) = falconpadded512_keypair();

        Seed::Falcon512 {
            pk: pk.as_bytes().to_vec(),
            sk: sk.as_bytes().to_vec(),
        }
    }

    pub fn expose(&self) -> Vec<u8> {
        match self {
            Seed::Ed25519 { seed } => seed.clone(),
            Seed::Falcon512 { pk, sk } => {
                let mut buf = Vec::with_capacity(FALCON512_SEED_LEN);
                buf.extend_from_slice(pk);
                buf.extend_from_slice(sk);
                buf
            }
        }
    }

    pub const fn len(&self) -> usize {
        match self {
            Seed::Ed25519 { .. } => ED25519_SEED_LEN,
            Seed::Falcon512 { .. } => FALCON512_SEED_LEN,
        }
    }
}

impl Debug for Seed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Seed({:?}, len={})", self.type_id(), self.len())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("'{0}' not found")]
    NotFound(String),

    #[error("'{0}'")]
    NotSupported(String),

    #[error("Seed backend '{0}' is not available (requires compile-time feature '{1}')")]
    BackendNotAvailable(String, String),

    #[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
    #[error("{0}")]
    Krs(#[from] KeyError),

    #[cfg(feature = "online-ssh-agent")]
    #[error("{0}")]
    SshAgent(#[from] ssh_agent_client_rs::Error),

    #[cfg(feature = "online-ssh-agent")]
    #[error("{0}")]
    Ssh(String),

    #[cfg(feature = "online-pkcs11")]
    #[error("{0}")]
    Pkcs11(#[from] cryptoki::error::Error),

    #[error("KRS worker thread disconnected unexpectedly")]
    WorkerDisconnect,
}

/// Select a backend based on a text value. Can return `BackendError` if the requested backend
/// is not supported (feature wasn't enabled at compile-time), or a backend corresponding to
/// the provided value doesn't exist.
pub fn try_choose_backend(backend: &str) -> Result<Box<dyn SeedBackend>, BackendError> {
    match backend.to_ascii_lowercase().as_str() {
        "memory" => Ok(Box::new(MemoryBackend::new()?)),
        "krs" => {
            #[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
            {
                return Ok(Box::new(LinuxKrsBackend::new()?));
            }

            #[allow(unreachable_code)] // conditional compilation
            Err(BackendError::BackendNotAvailable(
                "krs".to_string(),
                "online-linux-krs".to_string(),
            ))
        }
        "sshagent" | "ssh-agent" => {
            #[cfg(feature = "online-ssh-agent")]
            {
                return Ok(Box::new(SshAgentBackend::new(None)?));
            }

            #[allow(unreachable_code)] // conditional compilation
            Err(BackendError::BackendNotAvailable(
                "ssh-agent".to_string(),
                "online-ssh-agent".to_string(),
            ))
        }
        "tpm" => todo!(),
        "yubikey" => todo!(),
        _ => unreachable!("invalid backend: {}", backend),
    }
}

// In the future, take a look at memfd_secret  https://man.archlinux.org/man/memfd_secret.2.en
// Downside is no glibc call for it, and only available in kernel 6.5+
