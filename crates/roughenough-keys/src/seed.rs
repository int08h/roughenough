use std::fmt::{Debug, Formatter};

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

/// Secret backends keep the secret/long-term key available for on-line use while protecting it from
/// unauthorized access.
#[allow(clippy::len_without_is_empty)]
pub trait SecretBackend {
    fn store_secret(&mut self, secret: Secret) -> Result<(), BackendError>;
    fn get_secret(&self) -> Result<Secret, BackendError>;
    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError>;
    fn secret_len(&self) -> usize;
    fn public_key(&self) -> PublicKey;
    fn public_key_bytes(&self) -> [u8; 32];
}

/// Secret value used to derive the keypair of a LongTermIdentity.
#[derive(ZeroizeOnDrop)]
pub struct Secret {
    value: Vec<u8>,
}

#[allow(clippy::len_without_is_empty)]
impl Secret {
    pub fn new(value: &[u8]) -> Self {
        assert_eq!(value.len(), 32, "secret must be 32 bytes");
        Self {
            value: Vec::from(value),
        }
    }

    pub fn new_random() -> Self {
        Secret::new(&random_bytes::<32>())
    }

    pub fn expose(&self) -> &[u8] {
        &self.value
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }
}

impl Debug for Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(len={})", self.len())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BackendError {
    #[error("'{0}' not found")]
    NotFound(String),

    #[error("'{0}'")]
    NotSupported(String),

    #[error("Secret backend '{0}' is not available (requires compile-time feature '{1}')")]
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
pub fn try_choose_backend(backend: &str) -> Result<Box<dyn SecretBackend>, BackendError> {
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
