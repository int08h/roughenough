use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use protocol::ToWire;
use protocol::cursor::ParseCursor;
use protocol::tags::{
    Certificate, MerkleRoot, PublicKey, Signature, SignedResponse, SupportedVersions, Version,
};
use protocol::util::ClockSource;

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
    version: Version,
    clock_source: ClockSource,
    template_srep: SignedResponse,
    signing_buf: Vec<u8>,
}

impl OnlineKey {
    pub fn new(version: Version, clock_source: ClockSource) -> OnlineKey {
        let mut srep = SignedResponse::default();
        srep.set_radi(SignedResponse::DEFAULT_RADI_SECONDS);
        srep.set_vers(&SupportedVersions::from([version].as_ref()));
        srep.set_ver(version);

        // Allocate buffer and load signing prefix to be reused for all future signatures
        let prefix = version.srep_prefix();
        let mut buf = Vec::with_capacity(prefix.len() + srep.wire_size());
        buf.extend_from_slice(prefix);
        buf.resize(buf.capacity(), 0);

        Self {
            signer: OnlineSigner::from_random(),
            cert: Certificate::default(),
            template_srep: srep,
            signing_buf: buf,
            version,
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
    /// * `root` - The Merkle tree root hash that commits to the batch of client requests being
    ///   processed. This root allows clients to verify their request was included in the batch.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `SignedResponse` - The complete SREP structure with timestamp, radius, versions, and root
    /// - `Signature` - Ed25519 signature over the SREP
    pub fn make_srep(&mut self, root: &MerkleRoot) -> (SignedResponse, Signature) {
        let mut srep = self.template_srep.clone();
        srep.set_root(root);
        srep.set_midp(self.clock_source.epoch_seconds());

        let prefix_len = self.version.srep_prefix().len();
        let total_len = prefix_len + srep.wire_size();

        // Serialize into signing_buf, which was appropriately sized at construction
        let mut cursor = ParseCursor::new(&mut self.signing_buf[prefix_len..total_len]);
        srep.to_wire(&mut cursor)
            .expect("SREP serialization should not fail");

        let sig_bytes: [u8; 64] = self.sign(&self.signing_buf[..total_len]);
        let sig = Signature::from(sig_bytes);

        (srep, sig)
    }
}

pub(crate) struct OnlineSigner {
    key_pair: Ed25519KeyPair,
}

impl OnlineSigner {
    /// Creates a new Signer using a randomly generated Ed25519 key pair.
    pub(crate) fn from_random() -> OnlineSigner {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        OnlineSigner { key_pair }
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key_bytes())
    }

    pub(crate) fn public_key_bytes(&self) -> [u8; 32] {
        self.key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("infallible")
    }

    /// Signs the provided data using the private key associated with this Signer.
    pub(crate) fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.key_pair
            .sign(data)
            .as_ref()
            .try_into()
            .expect("infallible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
