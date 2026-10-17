use std::fmt::{Debug, Formatter};

#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
use linux_keyutils::KeyError;
use roughenough_protocol::tags::PublicKey;
use zeroize::Zeroize;

#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
pub use crate::online::linuxkrs::*;
pub use crate::online::memory::*;
#[cfg(feature = "online-ssh-agent")]
pub use crate::online::sshagent::*;

/// Seed backends keep the seed/long-term key available for on-line use while protecting it from
/// unauthorized access.
#[allow(clippy::len_without_is_empty)]
pub trait SeedBackend: Send {
    fn store_seed(&mut self, seed: Seed) -> Result<(), BackendError>;
    fn get_seed(&self) -> Result<Seed, BackendError>;
    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError>;
    fn seed_len(&self) -> usize;
    fn public_key(&self) -> PublicKey;
    fn public_key_bytes(&self) -> [u8; 32];
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
        "pkcs11" => {
            #[cfg(feature = "online-pkcs11")]
            {
                return pkcs11_from_env();
            }

            #[allow(unreachable_code)] // conditional compilation
            Err(BackendError::BackendNotAvailable(
                "pkcs11".to_string(),
                "online-pkcs11".to_string(),
            ))
        }
        "tpm" | "yubikey" => Err(BackendError::NotSupported(format!(
            "seed backend '{backend}' is not implemented"
        ))),
        other => Err(BackendError::NotSupported(format!(
            "unknown seed backend '{other}'"
        ))),
    }
}

/// Environment variable choosing which PKCS#11 module library to load.
pub const PKCS11_LIBRARY_ENV: &str = "ROUGHENOUGH_PKCS11_LIBRARY";
/// Environment variable selecting the token slot index; defaults to 0 when unset.
pub const PKCS11_SLOT_ENV: &str = "ROUGHENOUGH_PKCS11_SLOT";
/// Environment variable holding the user PIN for the token.
pub const PKCS11_PIN_ENV: &str = "ROUGHENOUGH_PKCS11_PIN";

// The module path, slot, and PIN come from the environment (rather than positional
// arguments) so backend selection stays a single string everywhere.
#[cfg(feature = "online-pkcs11")]
fn pkcs11_from_env() -> Result<Box<dyn SeedBackend>, BackendError> {
    use crate::online::pkcs11::Pkcs11Backend;

    let lib_path = std::env::var(PKCS11_LIBRARY_ENV).map_err(|_| {
        BackendError::NotFound(format!(
            "{PKCS11_LIBRARY_ENV} is not set (path to the PKCS#11 module library)"
        ))
    })?;

    let slot_index = match std::env::var(PKCS11_SLOT_ENV) {
        Ok(value) => value.parse::<usize>().map_err(|_| {
            BackendError::NotSupported(format!(
                "{PKCS11_SLOT_ENV} must be a non-negative integer, found '{value}'"
            ))
        })?,
        Err(_) => 0,
    };

    let pin = std::env::var(PKCS11_PIN_ENV).map_err(|_| {
        BackendError::NotFound(format!(
            "{PKCS11_PIN_ENV} is not set (user PIN for the token)"
        ))
    })?;

    Ok(Box::new(Pkcs11Backend::new(&lib_path, slot_index, &pin)?))
}

// In the future, take a look at memfd_secret  https://man.archlinux.org/man/memfd_secret.2.en
// Downside is no glibc call for it, and only available in kernel 6.5+

#[cfg(test)]
mod tests {
    use super::*;

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

    // Regression: these arms were todo!()/unreachable!() panics in a pub fn
    // taking an arbitrary &str
    #[test]
    fn unimplemented_and_unknown_backends_return_err_not_panic() {
        for name in ["tpm", "yubikey", "garbage", "TPM", ""] {
            match try_choose_backend(name) {
                Err(BackendError::NotSupported(_)) => {}
                Ok(_) => panic!("backend '{name}' should not construct"),
                Err(other) => panic!("backend '{name}': unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn memory_backend_is_always_available() {
        assert!(try_choose_backend("memory").is_ok());
        assert!(try_choose_backend("MEMORY").is_ok());
    }

    #[cfg(not(feature = "online-pkcs11"))]
    #[test]
    fn pkcs11_without_feature_is_backend_not_available() {
        match try_choose_backend("pkcs11") {
            Err(BackendError::BackendNotAvailable(backend, feature)) => {
                assert_eq!(backend, "pkcs11");
                assert_eq!(feature, "online-pkcs11");
            }
            Ok(_) => panic!("expected BackendNotAvailable, got Ok"),
            Err(other) => panic!("expected BackendNotAvailable, got {other:?}"),
        }
    }

    #[cfg(feature = "online-pkcs11")]
    #[test]
    fn pkcs11_with_feature_proceeds_past_selection() {
        // Construction may fail without a token/library configured, but the
        // selection itself must succeed: any error is NOT BackendNotAvailable
        match try_choose_backend("pkcs11") {
            Ok(_) => {}
            Err(BackendError::BackendNotAvailable(backend, feature)) => {
                panic!("pkcs11 selection failed with feature enabled: {backend} {feature}")
            }
            Err(_) => {}
        }
    }
}
