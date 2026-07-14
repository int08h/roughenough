use roughenough_protocol::ToWire;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::tags::{
    Certificate, MerkleRoot, ProtocolVersion, PublicKey, Signature, SignedResponse,
    SupportedVersions,
};
use roughenough_protocol::util::ClockSource;
use zeroize::Zeroizing;

use super::aws_lc_ed25519;

/// RFC 5.2.6: The PUBK tag MUST contain a temporary 32-byte Ed25519 public key
/// which is used to sign the SREP tag.
///
/// An OnLineKey is a randomly generated key pair signed with the server's `LongTermIdentity`
/// with a time-bounded validity period. `OnlineKey`s are used to create SREP (signed response)
/// messages which authenticate the server's responses to clients.
///
/// Create an `OnlineKey` by calling `LongTermIdentity::make_online_key()`
pub struct OnlineKey {
    signer: OnlineSigner,
    cert: Certificate,
    clock_source: ClockSource,
    template_srep: SignedResponse,
    signing_buf: Vec<u8>,
}

impl OnlineKey {
    pub fn new(clock_source: ClockSource) -> OnlineKey {
        let mut srep = SignedResponse::default();
        srep.set_radi(SignedResponse::DEFAULT_RADI_SECONDS);
        // RFC 5.2.5: VERS lists the versions the server advertises
        srep.set_vers(&SupportedVersions::from(
            ProtocolVersion::ADVERTISED.as_ref(),
        ));

        // Reusable signing buffer sized for the largest context string among
        // the supported versions
        let max_prefix_len = ProtocolVersion::ADVERTISED
            .iter()
            .map(|version| version.srep_prefix().len())
            .max()
            .expect("ADVERTISED is non-empty");
        let buf = vec![0u8; max_prefix_len + srep.wire_size()];

        Self {
            signer: OnlineSigner::from_random(),
            cert: Certificate::default(),
            template_srep: srep,
            signing_buf: buf,
            clock_source,
        }
    }

    pub(crate) fn set_cert(&mut self, cert: Certificate) {
        self.cert = cert;
    }

    /// Retrieves the delegation certificate (CERT) associated with this OnlineKey
    pub fn cert(&self) -> &Certificate {
        debug_assert!(
            self.cert != Certificate::default(),
            "logic error to use an OnlineKey without setting a delegation certificate"
        );

        &self.cert
    }

    /// Retrieves the public key associated with this OnlineKey.
    pub fn public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    /// Retrieves the raw public key bytes associated with this OnlineKey.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signer.public_key_bytes()
    }

    /// Signs the provided data using the private key associated with this OnlineKey.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signer.sign(data)
    }

    /// Creates a signed response (SREP) and corresponding cryptographic signature (SIG).
    ///
    /// This method generates a `SignedResponse` containing the current timestamp, server radius,
    /// protocol version information, and the provided Merkle root. The SREP is then signed with
    /// this online key.
    ///
    /// # Arguments
    ///
    /// * `version` - The protocol version negotiated for this response (RFC
    ///   5.2.5: the response VER should be one the client offered)
    /// * `root` - The Merkle tree root hash that commits to the batch of client requests being
    ///   processed. This root allows clients to verify their request was included in the batch.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `SignedResponse` - The complete SREP structure with timestamp, radius, versions, and root
    /// - `Signature` - Ed25519 signature over the SREP
    pub fn make_srep(
        &mut self,
        version: ProtocolVersion,
        root: &MerkleRoot,
    ) -> (SignedResponse, Signature) {
        let mut srep = self.template_srep.clone();
        srep.set_ver(version);
        srep.set_root(root);
        srep.set_midp(self.clock_source.epoch_seconds());

        // RFC 5.2.5: VERS MUST contain the version in this response's VER tag.
        // Draft versions outside ADVERTISED are added alongside the RFC version.
        if !ProtocolVersion::ADVERTISED.contains(&version) {
            srep.set_vers(&SupportedVersions::new(&[ProtocolVersion::RFC, version]));
        }
        debug_assert_eq!(srep.wire_size(), self.template_srep.wire_size());

        let prefix = version.srep_prefix();
        let prefix_len = prefix.len();
        let total_len = prefix_len + srep.wire_size();

        self.signing_buf[..prefix_len].copy_from_slice(prefix);
        let mut cursor = ParseCursor::new(&mut self.signing_buf[prefix_len..total_len]);
        srep.to_wire(&mut cursor)
            .expect("SREP serialization should not fail");

        let sig_bytes: [u8; 64] = self.sign(&self.signing_buf[..total_len]);
        let sig = Signature::from(sig_bytes);

        (srep, sig)
    }
}

pub(crate) struct OnlineSigner {
    key_pair: aws_lc_ed25519::KeyPair,
}

impl OnlineSigner {
    /// Creates a new Signer using a randomly generated Ed25519 key pair.
    pub(crate) fn from_random() -> OnlineSigner {
        let mut seed = Zeroizing::new([0; aws_lc_ed25519::SEED_LEN]);
        aws_lc_rs::rand::fill(seed.as_mut()).expect("Ed25519 seed generation failed");
        Self::from_seed(&seed)
    }

    fn from_seed(seed: &[u8; aws_lc_ed25519::SEED_LEN]) -> OnlineSigner {
        OnlineSigner {
            key_pair: aws_lc_ed25519::keypair_from_seed(seed),
        }
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key_bytes())
    }

    pub(crate) fn public_key_bytes(&self) -> [u8; 32] {
        self.key_pair.public_key
    }

    /// Signs the provided data using the private key associated with this Signer.
    pub(crate) fn sign(&self, data: &[u8]) -> [u8; 64] {
        aws_lc_ed25519::sign(&self.key_pair.private_key, data).expect("Ed25519 signing failed")
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

        let signer = OnlineSigner::from_seed(&seed);

        assert_eq!(signer.public_key_bytes(), expected_public_key);
        assert_eq!(signer.sign(b""), expected_signature);
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

        let signer = OnlineSigner::from_seed(&seed);

        assert_eq!(signer.public_key_bytes(), expected_public_key);
        assert_eq!(signer.sign(&[0xaf, 0x82]), expected_signature);
    }

    #[test]
    fn from_random_produces_different_keys() {
        // Generate multiple keys
        let signers: Vec<_> = (0..10).map(|_| OnlineSigner::from_random()).collect();

        // Verify all public keys are different
        let pubkeys: Vec<_> = signers.iter().map(|s| s.public_key_bytes()).collect();

        for i in 0..pubkeys.len() {
            for j in (i + 1)..pubkeys.len() {
                assert_ne!(pubkeys[i], pubkeys[j], "Generated keys should be different");
            }
        }
    }

    #[test]
    fn public_key_methods_are_consistent() {
        let signer = OnlineSigner::from_random();

        // Get public key via both methods
        let pubkey = signer.public_key();
        let pubkey_bytes = signer.public_key_bytes();

        // Verify they represent the same key
        assert_eq!(pubkey.as_ref(), &pubkey_bytes);

        // Verify conversion roundtrip
        let pubkey_from_bytes = PublicKey::from(pubkey_bytes);
        assert_eq!(pubkey, pubkey_from_bytes);
    }
}
