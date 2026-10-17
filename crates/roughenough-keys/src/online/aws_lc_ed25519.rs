//! Minimal safe wrapper around aws-lc-sys Ed25519 signing.
//!
//! The safe aws-lc-rs Ed25519 API heap-allocates twice per signature: a Rust-side
//! Vec holding the signature, and a C-side EVP_PKEY_CTX inside EVP_DigestSignInit
//! (only the Vec is visible to Rust's global allocator). AWS-LC's raw Ed25519
//! functions are stack-only, so calling them directly keeps signing allocation-free.

use std::fmt::{Debug, Formatter};

use roughenough_protocol::tags::PublicKey;
use zeroize::Zeroizing;

const PRIVATE_KEY_LEN: usize = 64;
const PUBLIC_KEY_LEN: usize = 32;
const SEED_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

pub(crate) struct KeyPair {
    private_key: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl KeyPair {
    #[allow(
        unsafe_code,
        reason = "FFI into AWS-LC; invariants documented at the call site"
    )]
    pub(crate) fn from_seed(seed: &[u8; SEED_LEN]) -> KeyPair {
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

    pub(crate) fn generate() -> KeyPair {
        let mut seed = Zeroizing::new([0; SEED_LEN]);
        aws_lc_rs::rand::fill(seed.as_mut()).expect("Ed25519 seed generation failed");
        KeyPair::from_seed(&seed)
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key)
    }

    #[allow(
        unsafe_code,
        reason = "FFI into AWS-LC; invariants documented at the call site"
    )]
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        let mut signature = [0; SIGNATURE_LEN];

        // SAFETY: All pointers refer to live buffers of the lengths required by AWS-LC;
        // message.len() describes the readable message region, including zero.
        // AWS-LC writes only the signature buffer and retains no pointers.
        let result = unsafe {
            aws_lc_sys::ED25519_sign(
                signature.as_mut_ptr(),
                message.as_ptr(),
                message.len(),
                self.private_key.as_ptr(),
            )
        };

        (result == 1)
            .then_some(signature)
            .expect("Ed25519 signing failed")
    }
}

impl Debug for KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(value.as_bytes())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn rfc8032_test_vector_1() {
        let seed = decode_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public_key =
            decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = decode_hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        let key_pair = KeyPair::from_seed(&seed);

        assert_eq!(key_pair.public_key().as_array(), &expected_public_key);
        assert_eq!(key_pair.sign(b""), expected_signature);
    }

    // Vector 1 signs the empty message; this one exercises the FFI message
    // pointer/length path with actual data
    #[test]
    fn rfc8032_test_vector_3() {
        let seed = decode_hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let expected_public_key =
            decode_hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let expected_signature = decode_hex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );

        let key_pair = KeyPair::from_seed(&seed);

        assert_eq!(key_pair.public_key().as_array(), &expected_public_key);
        assert_eq!(key_pair.sign(&[0xaf, 0x82]), expected_signature);
    }

    #[test]
    fn generate_produces_different_keys() {
        // Generate multiple keys
        let key_pairs: Vec<_> = (0..10).map(|_| KeyPair::generate()).collect();

        // Verify all public keys are different
        let pubkeys: Vec<_> = key_pairs.iter().map(|k| k.public_key()).collect();

        for i in 0..pubkeys.len() {
            for j in (i + 1)..pubkeys.len() {
                assert_ne!(pubkeys[i], pubkeys[j], "Generated keys should be different");
            }
        }
    }

    #[test]
    fn public_key_methods_are_consistent() {
        let key_pair = KeyPair::generate();

        // The PublicKey tag carries the key pair's raw public key bytes
        let pubkey = key_pair.public_key();
        assert_eq!(pubkey.as_ref(), &key_pair.public_key);

        // Verify conversion roundtrip
        let pubkey_from_bytes = PublicKey::from(key_pair.public_key);
        assert_eq!(pubkey, pubkey_from_bytes);
    }
}
