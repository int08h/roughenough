use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};

use crate::seed::SeedBackend;

// Only the device-backed backends' tests log, so gate on the same cfgs to avoid dead code
#[cfg(any(
    all(target_os = "linux", feature = "online-linux-krs"),
    feature = "online-ssh-agent",
    feature = "online-pkcs11"
))]
pub(crate) fn enable_logging() {
    // try_init installs a global subscriber once; later calls are harmless no-ops
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .compact()
        .try_init();
}

pub(crate) fn assert_backend_signs(backend: &mut dyn SeedBackend) {
    let data = b"hello world";
    let signature = backend.sign(data).unwrap();

    let public_key = backend.public_key();
    let verifier = UnparsedPublicKey::new(&ED25519, public_key.as_ref());
    verifier.verify(data, &signature).unwrap();
}
