//! Cryptographic utilities shared across the project

use aws_lc_rs::digest::{SHA512, digest};
use protocol::ToFrame;
use protocol::response::Response;
use protocol::tags::{Nonce, PublicKey, SrvCommitment};

/// Calculate the chained nonce from a prior response and random value.
/// Returns `SHA512(prior_response_frame || rand)[0:32]`
pub fn calculate_chained_nonce(prior_response: &Response, rand: &[u8]) -> Nonce {
    let mut chain_value = prior_response
        .as_frame_bytes()
        .expect("should be infallible")
        .to_vec();

    chain_value.extend_from_slice(rand);

    let digest = digest(&SHA512, &chain_value);
    Nonce::from(&digest.as_ref()[..32])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_chained_nonce() {
        let prior_response = Response::default();
        let rand = [0x42u8; 32];

        let nonce1 = calculate_chained_nonce(&prior_response, &rand);
        let nonce2 = calculate_chained_nonce(&prior_response, &rand);

        // Should be deterministic
        assert_eq!(nonce1, nonce2);
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
}
