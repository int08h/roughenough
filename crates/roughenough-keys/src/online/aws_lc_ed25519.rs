//! Minimal safe wrapper around aws-lc-sys Ed25519 signing.
//!
//! The safe aws-lc-rs Ed25519 API heap-allocates twice per signature: a Rust-side
//! Vec holding the signature, and a C-side EVP_PKEY_CTX inside EVP_DigestSignInit
//! (only the Vec is visible to Rust's global allocator). AWS-LC's raw Ed25519
//! functions are stack-only, so calling them directly keeps signing allocation-free.

use zeroize::Zeroizing;

pub(super) const PRIVATE_KEY_LEN: usize = 64;
pub(super) const PUBLIC_KEY_LEN: usize = 32;
pub(super) const SEED_LEN: usize = 32;
pub(super) const SIGNATURE_LEN: usize = 64;

pub(super) struct KeyPair {
    pub(super) private_key: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    pub(super) public_key: [u8; PUBLIC_KEY_LEN],
}

#[allow(
    unsafe_code,
    reason = "FFI into AWS-LC; invariants documented at the call site"
)]
pub(super) fn keypair_from_seed(seed: &[u8; SEED_LEN]) -> KeyPair {
    let mut public_key = [0; PUBLIC_KEY_LEN];
    let mut private_key = Zeroizing::new([0; PRIVATE_KEY_LEN]);

    // SAFETY: The fixed-size arrays satisfy AWS-LC's required 32-byte seed, 32-byte
    // public-key, and 64-byte private-key buffers. AWS-LC does not retain them.
    unsafe {
        aws_lc_sys::ED25519_keypair_from_seed(
            public_key.as_mut_ptr(),
            private_key.as_mut_ptr(),
            seed.as_ptr(),
        );
    }

    KeyPair {
        private_key,
        public_key,
    }
}

#[allow(
    unsafe_code,
    reason = "FFI into AWS-LC; invariants documented at the call site"
)]
pub(super) fn sign(
    private_key: &[u8; PRIVATE_KEY_LEN],
    message: &[u8],
) -> Option<[u8; SIGNATURE_LEN]> {
    let mut signature = [0; SIGNATURE_LEN];

    // SAFETY: All pointers refer to live buffers of the lengths required by AWS-LC;
    // message.len() describes the readable message region, including zero.
    // AWS-LC writes only the signature buffer and retains no pointers.
    let result = unsafe {
        aws_lc_sys::ED25519_sign(
            signature.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            private_key.as_ptr(),
        )
    };

    (result == 1).then_some(signature)
}
