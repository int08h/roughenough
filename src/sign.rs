//!
//! Ed25519 signing and verification
//!

extern crate ring;
extern crate untrusted;

use hex::*;
use {CERTIFICATE_CONTEXT, SIGNED_RESPONSE_CONTEXT, TREE_LEAF_TWEAK};

use self::ring::{digest, error, signature};
use self::ring::signature::Ed25519KeyPair;

use self::untrusted::Input;

pub fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk = Input::from(pubkey);
    let msg = Input::from(message);
    let sig = Input::from(signature);

    match signature::verify(&signature::ED25519, pk, msg, sig) {
        Ok(_) => true,
        _ => false
    }
}

pub fn sign_ed25519(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(Input::from(&seed))?;
    Ok(key_pair.sign(message).as_ref().to_vec())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_ed25519_sig_on_empty_message() {
        let pubkey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".from_hex().unwrap();
        let empty_msg = [0u8; 0];
        let signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b".from_hex().unwrap();

        let result = verify_ed25519(&pubkey, &empty_msg, &signature);
        assert_eq!(result, true);
    }

    #[test]
    fn verify_ed25519_sig() {
		let pubkey = "c0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7".from_hex().unwrap();
		let message = "5f4c8989".from_hex().unwrap();
		let signature = "124f6fc6b0d100842769e71bd530664d888df8507df6c56dedfdb509aeb93416e26b918d38aa06305df3095697c18b2aa832eaa52edc0ae49fbae5a85e150c07".from_hex().unwrap();

        let result = verify_ed25519(&pubkey, &message, &signature);
        assert_eq!(result, true);
    }

    #[test]
    fn sign_ed25519_empty_message() {
		let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".from_hex().unwrap();
        let empty_msg = [0u8; 0];
		let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b".from_hex().unwrap();
		
		let result = sign_ed25519(&seed, &empty_msg).unwrap();
		assert_eq!(result, expected_sig);
    }

    #[test]
    fn sign_ed25519_message() {
		let seed = "0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9".from_hex().unwrap();
		let message = "cbc77b".from_hex().unwrap();
		let expected_sig = "d9868d52c2bebce5f3fa5a79891970f309cb6591e3e1702a70276fa97c24b3a8e58606c38c9758529da50ee31b8219cba45271c689afa60b0ea26c99db19b00c".from_hex().unwrap();

		let result = sign_ed25519(&seed, &message).unwrap();
		assert_eq!(result, expected_sig);
    }

    #[test]
    fn sign_verify_round_trip() {
        let seed = "334a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9".from_hex().unwrap();
        let message = "Hello world".as_bytes();

        let signature = sign_ed25519(&seed, &message).unwrap();

        let key_pair = Ed25519KeyPair::from_seed_unchecked(Input::from(&seed)).unwrap();
        let result = verify_ed25519(key_pair.public_key_bytes(), &message, &signature);

        assert_eq!(result, true);
    }

}
