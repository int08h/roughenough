//! Linux Key Retention Service (KRS) backend that keeps the Ed25519 seed in the kernel's
//! thread-specific keyring.
//!
//! It would be nice if only the **signing operation** was available to the thread, not the seed
//! contents. However, Linux doesn't support Ed25519 as a PKCS8 parsable asymmetric private key
//! type. Only RSA are supported for that. :(
//!
//! Load kernel modules
//! ```text
//! $ sudo modprobe pkcs8_key_parser
//! $ sudo modprobe curve25519-x86_64
//! ```
//!
//! Works for RSA:
//! ```text
//! $ openssl genrsa -out priv.pem
//! $ openssl rsa -in priv.pem -pubout -out pub.pem
//! writing RSA key
//! $ openssl pkcs8 -in priv.pem -topk8 -outform DER -nocrypt -out priv.p8
//! $ cat priv.p8 | keyctl padd asymmetric "rsa-key" @s
//! 717848853
//! $ echo abc | openssl sha256 -binary > abc.sha256
//! $ keyctl pkey_sign %asymmetric:rsa-key 0 abc.sha256 enc=pkcs1 hash=sha256 > abc.sig
//! $ echo abc | openssl sha256 -verify pub.pem -signature abc.sig
//! Verified OK
//! ```
//!
//! But not for Ed25519
//! ```text
//! $ openssl genpkey -algorithm ed25519 -out ed-private.pem
//! $ openssl pkey -in ed-private.pem -pubout -out ed-public.pem
//! $ openssl pkcs8 -in ed-private.pem -topk8 -outform DER -nocrypt -out ed-private.p8
//! $ cat ed-private.p8 | keyctl padd asymmetric "a_name_for_the_key" @s
//! add_key: Package not installed
//! ```

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use linux_keyutils::{KeyError, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
use roughenough_protocol::tags::PublicKey;
use tracing::{debug, error};
use zeroize::Zeroizing;

use crate::online::aws_lc_ed25519::KeyPair;
use crate::seed::{BackendError, Seed, SeedBackend};

const KEY_NAME: &str = "roughenough-seed";

type Job = Box<dyn FnOnce(&KeyRing) + Send>;

/// Linux Key Retention Service (KRS) backend that stores Ed25519 seed material in the kernel's
/// thread-specific keyring. Since KeyRing is inherently thread-local, a dedicated worker thread
/// owns the KeyRing and runs every operation as a job sent over a channel, enabling access from
/// any thread while maintaining the KeyRing's thread-locality constraints.
pub struct LinuxKrsBackend {
    jobs: Option<Sender<Job>>,
    worker: Option<JoinHandle<()>>,
    public_key: PublicKey,
}

impl LinuxKrsBackend {
    /// Spawns the worker thread and stores `seed` in its keyring
    pub fn new(seed: Seed) -> Result<LinuxKrsBackend, BackendError> {
        let key_pair = KeyPair::from_seed(seed.expose());
        let public_key = key_pair.public_key();

        let (jobs, jobs_rx) = mpsc::channel();
        let worker = thread::spawn(move || worker_thread(jobs_rx));

        // Built before storing the seed so that a failed store still closes the channel and
        // joins the worker thread through Drop
        let backend = LinuxKrsBackend {
            jobs: Some(jobs),
            worker: Some(worker),
            public_key,
        };

        backend.call(move |ring| store_seed(ring, seed))?;

        debug!("initialized linux KRS backend");

        Ok(backend)
    }

    #[cfg(test)]
    fn read_seed(&self) -> Result<Seed, BackendError> {
        self.call(load_seed)
    }

    /// Runs `f` on the worker thread and waits for its result
    fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&KeyRing) -> Result<R, BackendError> + Send + 'static,
    ) -> Result<R, BackendError> {
        let (result_tx, result_rx) = mpsc::channel();
        let job: Job = Box::new(move |ring: &KeyRing| {
            let _ = result_tx.send(f(ring));
        });

        self.jobs
            .as_ref()
            .expect("set until drop")
            .send(job)
            .map_err(|_| BackendError::WorkerDisconnect)?;

        result_rx
            .recv()
            .map_err(|_| BackendError::WorkerDisconnect)?
    }
}

/// Owns the thread-specific KeyRing and runs jobs until the channel closes. If the keyring is
/// unusable it returns early, and callers see `BackendError::WorkerDisconnect`.
fn worker_thread(jobs: Receiver<Job>) {
    let thread_key_ring = match KeyRing::from_special_id(KeyRingIdentifier::Thread, true) {
        Ok(keyring) => keyring,
        Err(e) => {
            error!("Failed to create thread-specific keyring: {}", e);
            return;
        }
    };

    // Ensure the key doesn't already exist
    match thread_key_ring.search(KEY_NAME) {
        Err(KeyError::KeyDoesNotExist) => {
            // Expected - the key should not exist
        }
        Err(e) => {
            error!("Error searching for existing key: {}", e);
            return;
        }
        Ok(key) => {
            error!(
                "'{}' already exists on the thread-specific keyring: {:?}",
                KEY_NAME, key
            );
            return;
        }
    }

    while let Ok(job) = jobs.recv() {
        job(&thread_key_ring);
    }

    if let Err(e) = thread_key_ring.clear() {
        error!("Error clearing keyring on shutdown: {}", e);
    } else {
        debug!("Cleared keyring on worker thread shutdown");
    }
}

fn store_seed(thread_key_ring: &KeyRing, seed: Seed) -> Result<(), BackendError> {
    let krs_key = thread_key_ring.add_key(KEY_NAME, seed.expose())?;

    // Set restrictive permissions
    let permissions = KeyPermissionsBuilder::builder()
        .posessor(Permission::ALL)
        // implicit: no permissions for anyone else
        .build();
    krs_key.set_perms(permissions)?;

    debug!("stored {}-byte seed as {:?}", Seed::LEN, krs_key.get_id());

    Ok(())
}

fn load_seed(thread_key_ring: &KeyRing) -> Result<Seed, BackendError> {
    match thread_key_ring.search(KEY_NAME) {
        Ok(seed_key) => {
            let mut buf = Zeroizing::new([0u8; Seed::LEN]);
            let nread = seed_key.read(&mut buf).map_err(BackendError::from)?;

            if nread != Seed::LEN {
                return Err(BackendError::NotFound(format!(
                    "Expected {}-byte seed, got {nread} bytes",
                    Seed::LEN
                )));
            }

            let seed = Seed::from_bytes(&buf);

            debug!(
                "read {}-byte seed '{}' from {:?}",
                nread,
                KEY_NAME,
                seed_key.get_id()
            );

            Ok(seed)
        }
        Err(KeyError::KeyDoesNotExist) => Err(BackendError::NotFound(KEY_NAME.to_string())),
        Err(e) => Err(BackendError::Krs(e)),
    }
}

impl SeedBackend for LinuxKrsBackend {
    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError> {
        let data = data.to_vec();
        self.call(move |ring| {
            let seed = load_seed(ring)?;
            let key_pair = KeyPair::from_seed(seed.expose());
            Ok(key_pair.sign(&data))
        })
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

impl Drop for LinuxKrsBackend {
    fn drop(&mut self) {
        // Closing the channel ends the worker's job loop, which then clears the keyring
        drop(self.jobs.take());

        if let Some(worker) = self.worker.take() {
            if let Err(e) = worker.join() {
                error!("Worker thread panicked: {:?}", e);
            } else {
                debug!("Worker thread shut down cleanly");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};

    use super::*;
    use crate::seed::SeedBackend;
    use crate::test_util::{assert_backend_signs, enable_logging};

    #[test]
    fn new_with_seed_succeeds() {
        enable_logging();

        // Should succeed
        LinuxKrsBackend::new(Seed::new_random()).unwrap();
    }

    #[test]
    fn read_what_we_stored_roundtrip() {
        enable_logging();

        // given a LinuxKrsBackend instance created with a seed
        let value = [99u8; 32];
        let backend = LinuxKrsBackend::new(Seed::from_bytes(&value)).unwrap();

        // then we can read it back
        let read = backend.read_seed().unwrap();
        assert_eq!(read.expose(), value.as_slice());
    }

    #[test]
    fn confirm_drop_clears_the_seed_key() {
        enable_logging();

        // given a LinuxKrsBackend instance created with a seed
        let value = [123u8; 32];
        let backend = LinuxKrsBackend::new(Seed::from_bytes(&value)).unwrap();

        // and we confirmed it's there
        let read = backend.read_seed().unwrap();
        assert_eq!(read.expose(), value.as_slice());

        // When we drop the backend, it should clear the keyring
        drop(backend);

        // A new backend with a different seed reads back its own seed, not the old one
        let new_value = [99u8; 32];
        let new_backend = LinuxKrsBackend::new(Seed::from_bytes(&new_value)).unwrap();
        let read = new_backend.read_seed().unwrap();
        assert_eq!(read.expose(), new_value.as_slice());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let mut backend = LinuxKrsBackend::new(Seed::new_random()).unwrap();
        assert_backend_signs(&mut backend);
    }

    #[test]
    fn concurrent_access_from_multiple_threads() {
        enable_logging();
        use std::sync::{Arc, Mutex};

        // Create a backend holding a seed
        let backend = Arc::new(Mutex::new(
            LinuxKrsBackend::new(Seed::new_random()).unwrap(),
        ));

        // Test concurrent access from multiple threads
        let mut handles = vec![];

        // Spawn multiple threads that perform operations
        for i in 0..5 {
            let backend_clone = Arc::clone(&backend);
            let handle = thread::spawn(move || {
                // Each thread performs multiple operations
                for j in 0..3 {
                    // Sign data
                    let data = format!("thread {i} iteration {j}");
                    let signature = backend_clone.lock().unwrap().sign(data.as_bytes()).unwrap();
                    assert_eq!(signature.len(), 64);

                    // Verify signature
                    let public_key = backend_clone.lock().unwrap().public_key();
                    let verifier = UnparsedPublicKey::new(&ED25519, public_key.as_array());
                    verifier.verify(data.as_bytes(), &signature).unwrap();
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn init_on_thread_1_then_ops_from_thread_2() {
        enable_logging();

        // Create backend on main thread
        let mut backend = LinuxKrsBackend::new(Seed::new_random()).unwrap();

        // Move backend to another thread and perform operations
        let handle = thread::spawn(move || {
            // These operations should work even though we're on a different thread
            backend.read_seed().unwrap();

            let data = b"cross-thread test";
            let signature = backend.sign(data).unwrap();
            assert_eq!(signature.len(), 64);

            backend
        });

        // Get backend back and verify it still works
        let backend = handle.join().unwrap();
        backend.read_seed().unwrap();
    }
}
