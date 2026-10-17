//! Cryptographic utilities shared across the project

use aws_lc_rs::digest::{SHA512, digest};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use roughenough_protocol::tags::{Nonce, PublicKey, SrvCommitment};

/// Calculate the chained nonce from a prior response and random value.
/// Returns `SHA512(prior_response_frame || rand)[0:32]`
///
/// `prior_response_frame` is the prior response packet exactly as received,
/// including the "ROUGHTIM" framing.
pub fn calculate_chained_nonce(prior_response_frame: &[u8], rand: &[u8]) -> Nonce {
    let mut chain_value = prior_response_frame.to_vec();
    chain_value.extend_from_slice(rand);

    let digest = digest(&SHA512, &chain_value);
    Nonce::try_from(&digest.as_ref()[..32]).expect("SHA-512 digest is 64 bytes")
}

/// Generate cryptographically secure random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut val = [0u8; N];
    aws_lc_rs::rand::fill(&mut val).expect("should be infallible");
    val
}

/// RFC 5.1.4: The value of the SRV tag is H(0xff || public_key) where public_key is
/// the server's long-term, 32-byte Ed25519 public key and H is SHA-512 truncated to
/// the first 32 bytes.
pub fn make_srv_commitment(pub_key: &PublicKey) -> SrvCommitment {
    let mut data = Vec::from(SrvCommitment::HASH_PREFIX_SRV);
    data.extend_from_slice(pub_key.as_ref());

    let digest = digest(&SHA512, &data);
    SrvCommitment::try_from(&digest.as_ref()[0..32]).expect("should be infallible")
}

/// Verify an Ed25519 `signature` over `context || message`. Roughtime signs SREP and DELE
/// with a version-specific context prefix (RFC 5.2).
pub fn verify_with_context(
    public_key: &[u8],
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let mut signed = Vec::with_capacity(context.len() + message.len());
    signed.extend_from_slice(context);
    signed.extend_from_slice(message);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signed, signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_chained_nonce() {
        let prior_response_frame = [0x5au8; 128];
        let rand = [0x42u8; 32];

        let nonce1 = calculate_chained_nonce(&prior_response_frame, &rand);
        let nonce2 = calculate_chained_nonce(&prior_response_frame, &rand);

        // Should be deterministic
        assert_eq!(nonce1, nonce2);

        // And sensitive to both inputs
        let other = calculate_chained_nonce(&prior_response_frame, &[0x43u8; 32]);
        assert_ne!(nonce1, other);
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes::<32>();
        let bytes2 = random_bytes::<32>();

        // Should be different (extremely high probability)
        assert_ne!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
    }

    #[test]
    fn test_make_srv_commitment() {
        let key_bytes = [0x01u8; 32];
        let pub_key = PublicKey::from(key_bytes);

        let commitment1 = make_srv_commitment(&pub_key);
        let commitment2 = make_srv_commitment(&pub_key);

        // Should be deterministic
        assert_eq!(commitment1, commitment2);
        assert_eq!(commitment1.as_ref().len(), 32);
    }

    #[test]
    fn verify_with_context_rejects_wrong_context() {
        use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

        let key_pair = Ed25519KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().as_ref();
        let message = b"message";

        let mut signed = b"context-a".to_vec();
        signed.extend_from_slice(message);
        let signature = key_pair.sign(&signed);

        assert!(verify_with_context(
            public_key,
            b"context-a",
            message,
            signature.as_ref()
        ));
        assert!(!verify_with_context(
            public_key,
            b"context-b",
            message,
            signature.as_ref()
        ));
        assert!(!verify_with_context(
            public_key,
            b"",
            message,
            signature.as_ref()
        ));
    }
}
