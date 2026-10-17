pub use krs_backend::LinuxKrsBackend;

// It would be nice if only the **signing operation** was available to the thread, not the seed
// contents. However, Linux doesn't support Ed25519 as a PKCS8 parsable asymmetric private key type.
// Only RSA are supported for that. :(
//
// Load kernel modules
// ```
// $ sudo modprobe pkcs8_key_parser
// $ sudo modprobe curve25519-x86_64
// ```
//
// Works for RSA:
// ```
// $ openssl genrsa -out priv.pem
// $ openssl rsa -in priv.pem -pubout -out pub.pem
// writing RSA key
// $ openssl pkcs8 -in priv.pem -topk8 -outform DER -nocrypt -out priv.p8
// $ cat priv.p8 | keyctl padd asymmetric "rsa-key" @s
// 717848853
// $ echo abc | openssl sha256 -binary > abc.sha256
// $ keyctl pkey_sign %asymmetric:rsa-key 0 abc.sha256 enc=pkcs1 hash=sha256 > abc.sig
// $ echo abc | openssl sha256 -verify pub.pem -signature abc.sig
// Verified OK
// ```
//
// But not for Ed25519
// ```
// $ openssl genpkey -algorithm ed25519 -out ed-private.pem
// $ openssl pkey -in ed-private.pem -pubout -out ed-public.pem
// $ openssl pkcs8 -in ed-private.pem -topk8 -outform DER -nocrypt -out ed-private.p8
// $ cat ed-private.p8 | keyctl padd asymmetric "a_name_for_the_key" @s
// add_key: Package not installed
// ```

#[cfg(target_os = "linux")]
pub mod krs_backend {
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread;

    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use linux_keyutils::{KeyError, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
    use roughenough_protocol::tags::PublicKey;
    use tracing::{debug, error};
    use zeroize::Zeroizing;

    use crate::seed::{BackendError, Seed, SeedBackend};

    /// Request types for the worker thread
    enum Request {
        StoreSeed {
            seed: Seed,
            response_tx: Sender<Result<(), BackendError>>,
        },
        #[cfg(test)]
        GetSeed {
            response_tx: Sender<Result<Seed, BackendError>>,
        },
        Sign {
            data: Vec<u8>,
            response_tx: Sender<Result<[u8; 64], BackendError>>,
        },
        Shutdown,
    }

    /// Linux Key Retention Service (KRS) backend that stores Ed25519 seed material in the kernel's
    /// thread-specific keyring. Since KeyRing is inherently thread-local, this implementation uses
    /// a dedicated worker thread that owns the KeyRing and processes all operations via mpsc channels.
    /// Each public method sends a request with an embedded response channel, enabling thread-safe
    /// access from any thread while maintaining the KeyRing's thread-locality constraints.
    pub struct LinuxKrsBackend {
        request_tx: Sender<Request>,
        worker_handle: Option<thread::JoinHandle<()>>,
        public_key: PublicKey,
    }

    impl LinuxKrsBackend {
        const KEY_NAME: &'static str = "roughenough-seed";

        /// Spawns the worker thread and stores `seed` in its keyring
        pub fn new(seed: Seed) -> Result<LinuxKrsBackend, BackendError> {
            let public_key = PublicKey::try_from(
                Ed25519KeyPair::from_seed_unchecked(seed.expose())
                    .expect("any 32-byte seed is valid")
                    .public_key()
                    .as_ref(),
            )
            .expect("Ed25519 public keys are 32 bytes");

            let (request_tx, request_rx) = mpsc::channel();

            let worker_handle = thread::spawn(move || {
                Self::worker_thread(request_rx);
            });

            // Built before storing the seed so that a failed store still shuts down and joins
            // the worker thread through Drop
            let backend = LinuxKrsBackend {
                request_tx,
                worker_handle: Some(worker_handle),
                public_key,
            };

            let (response_tx, response_rx) = mpsc::channel();
            backend
                .request_tx
                .send(Request::StoreSeed { seed, response_tx })
                .map_err(|_| BackendError::WorkerDisconnect)?;

            response_rx
                .recv()
                .map_err(|_| BackendError::WorkerDisconnect)??;

            debug!("initialized linux KRS backend");

            Ok(backend)
        }

        #[cfg(test)]
        fn read_seed(&self) -> Result<Seed, BackendError> {
            let (response_tx, response_rx) = mpsc::channel();
            self.request_tx
                .send(Request::GetSeed { response_tx })
                .map_err(|_| BackendError::WorkerDisconnect)?;

            response_rx
                .recv()
                .map_err(|_| BackendError::WorkerDisconnect)?
        }

        /// Worker thread that owns the KeyRing and processes requests
        fn worker_thread(request_rx: Receiver<Request>) {
            let thread_key_ring = match KeyRing::from_special_id(KeyRingIdentifier::Thread, true) {
                Ok(keyring) => keyring,
                Err(e) => {
                    error!("Failed to create thread-specific keyring: {}", e);
                    return;
                }
            };

            // Ensure the key doesn't already exist
            match thread_key_ring.search(Self::KEY_NAME) {
                Err(KeyError::KeyDoesNotExist) => {
                    // Expected - the key should not exist
                }
                Err(e) => {
                    error!("Error searching for existing key: {}", e);
                    return;
                }
                Ok(key) => {
                    panic!(
                        "impossible: '{}' already exists on the thread-specific keyring: {:?}",
                        Self::KEY_NAME,
                        key
                    );
                }
            }

            // Process requests
            while let Ok(request) = request_rx.recv() {
                match request {
                    Request::StoreSeed { seed, response_tx } => {
                        let result = Self::handle_store_seed(&thread_key_ring, seed);
                        let _ = response_tx.send(result);
                    }
                    #[cfg(test)]
                    Request::GetSeed { response_tx } => {
                        let result = Self::handle_get_seed(&thread_key_ring);
                        let _ = response_tx.send(result);
                    }
                    Request::Sign { data, response_tx } => {
                        let result = Self::handle_sign(&thread_key_ring, &data);
                        let _ = response_tx.send(result);
                    }
                    Request::Shutdown => {
                        debug!("Worker thread shutting down");
                        break;
                    }
                }
            }

            // Clean up on shutdown
            if let Err(e) = thread_key_ring.clear() {
                error!("Error clearing keyring on shutdown: {}", e);
            } else {
                debug!("Cleared keyring on worker thread shutdown");
            }
        }

        fn handle_store_seed(thread_key_ring: &KeyRing, seed: Seed) -> Result<(), BackendError> {
            // Check if key already exists
            if thread_key_ring.search(Self::KEY_NAME).is_ok() {
                panic!("{} already exists somehow?", Self::KEY_NAME);
            }

            let krs_key = thread_key_ring.add_key(Self::KEY_NAME, seed.expose())?;

            // Set restrictive permissions
            let permissions = KeyPermissionsBuilder::builder()
                .posessor(Permission::ALL)
                // implicit: no permissions for anyone else
                .build();
            krs_key.set_perms(permissions)?;

            debug!("stored {}-byte seed as {:?}", Seed::LEN, krs_key.get_id());

            Ok(())
        }

        fn handle_get_seed(thread_key_ring: &KeyRing) -> Result<Seed, BackendError> {
            match thread_key_ring.search(Self::KEY_NAME) {
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
                        Self::KEY_NAME,
                        seed_key.get_id()
                    );

                    Ok(seed)
                }
                Err(KeyError::KeyDoesNotExist) => {
                    Err(BackendError::NotFound(Self::KEY_NAME.to_string()))
                }
                Err(e) => Err(BackendError::Krs(e)),
            }
        }

        fn handle_sign(thread_key_ring: &KeyRing, data: &[u8]) -> Result<[u8; 64], BackendError> {
            let seed = Self::handle_get_seed(thread_key_ring)?;
            let keypair = Ed25519KeyPair::from_seed_unchecked(seed.expose()).unwrap();
            let signature = keypair.sign(data);
            Ok(signature.as_ref().try_into().expect("infallible"))
        }
    }

    impl SeedBackend for LinuxKrsBackend {
        fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError> {
            let (response_tx, response_rx) = mpsc::channel();
            self.request_tx
                .send(Request::Sign {
                    data: data.to_vec(),
                    response_tx,
                })
                .map_err(|_| BackendError::WorkerDisconnect)?;

            response_rx
                .recv()
                .map_err(|_| BackendError::WorkerDisconnect)?
        }

        fn public_key(&self) -> PublicKey {
            self.public_key
        }
    }

    impl Drop for LinuxKrsBackend {
        fn drop(&mut self) {
            // Send shutdown request
            if let Err(e) = self.request_tx.send(Request::Shutdown) {
                error!("Failed to send shutdown request: {}", e);
            }

            // Wait for worker thread to finish
            if let Some(handle) = self.worker_handle.take() {
                if let Err(e) = handle.join() {
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
        use crate::online::test_util::enable_logging;
        use crate::seed::SeedBackend;

        #[test]
        fn init_keyring_succeeds() {
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
            // Given a LinuxKrsBackend
            let mut backend = LinuxKrsBackend::new(Seed::new_random()).unwrap();

            // When the backend signs something
            let data = b"hello world";
            let signature = backend.sign(data).unwrap();

            // Then that signature validates with aws-lc-rs
            let public_key = backend.public_key();
            let verifier = UnparsedPublicKey::new(&ED25519, public_key.as_array());
            verifier.verify(data, &signature).unwrap();
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
                        let signature =
                            backend_clone.lock().unwrap().sign(data.as_bytes()).unwrap();
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
}
