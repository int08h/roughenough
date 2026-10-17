use roughenough_common::clocksource::ClockSource;
use roughenough_protocol::ToWire;
use roughenough_protocol::cursor::ParseCursor;
use roughenough_protocol::tags::{
    Certificate, MerkleRoot, ProtocolVersion, PublicKey, Signature, SignedResponse,
    SupportedVersions,
};

use super::aws_lc_ed25519::KeyPair;

/// RFC 5.2.6: The PUBK tag MUST contain a temporary 32-byte Ed25519 public key
/// which is used to sign the SREP tag.
///
/// An OnLineKey is a randomly generated key pair signed with the server's `LongTermIdentity`
/// with a time-bounded validity period. `OnlineKey`s are used to create SREP (signed response)
/// messages which authenticate the server's responses to clients.
///
/// Create an `OnlineKey` by calling `LongTermIdentity::make_online_key()`
pub struct OnlineKey {
    key_pair: KeyPair,
    cert: Certificate,
    clock_source: ClockSource,
    template_srep: SignedResponse,
    signing_buf: Vec<u8>,
}

impl OnlineKey {
    pub(crate) fn new(
        key_pair: KeyPair,
        cert: Certificate,
        clock_source: ClockSource,
    ) -> OnlineKey {
        let mut srep = SignedResponse::default();
        srep.set_radi(SignedResponse::DEFAULT_RADI_SECONDS);
        // RFC 5.2.5: VERS lists the versions the server advertises
        srep.set_vers(&SupportedVersions::from(
            ProtocolVersion::ADVERTISED.as_ref(),
        ));

        // Reusable signing buffer sized for the context string plus SREP
        let prefix_len = ProtocolVersion::ADVERTISED
            .iter()
            .map(|v| v.srep_prefix().len())
            .max()
            .unwrap_or(0);
        let buf = vec![0u8; prefix_len + srep.wire_size()];

        Self {
            key_pair,
            cert,
            template_srep: srep,
            signing_buf: buf,
            clock_source,
        }
    }

    /// Retrieves the delegation certificate (CERT) associated with this OnlineKey
    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    /// Retrieves the public key associated with this OnlineKey.
    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public_key()
    }

    /// Retrieves the raw public key bytes associated with this OnlineKey.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.key_pair.public_key().as_array()
    }

    /// Creates a signed response (SREP) and corresponding cryptographic signature (SIG).
    ///
    /// This method generates a `SignedResponse` containing the current timestamp, server radius,
    /// protocol version information, and the provided Merkle root. The SREP is then signed with
    /// this online key.
    ///
    /// # Arguments
    ///
    /// * `version` - The protocol version negotiated for this response, one of
    ///   [`ProtocolVersion::ADVERTISED`] (RFC 5.2.5: the response VER should be
    ///   one the client offered)
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
        // RFC 5.2.5: VERS MUST contain the version in this response's VER tag
        debug_assert!(
            ProtocolVersion::ADVERTISED.contains(&version),
            "{version:?} is not advertised"
        );

        let mut srep = self.template_srep.clone();
        srep.set_ver(version);
        srep.set_root(root);
        srep.set_midp(self.clock_source.epoch_seconds());

        let prefix = version.srep_prefix();
        let prefix_len = prefix.len();
        let total_len = prefix_len + srep.wire_size();

        self.signing_buf[..prefix_len].copy_from_slice(prefix);
        let mut cursor = ParseCursor::new(&mut self.signing_buf[prefix_len..total_len]);
        srep.to_wire(&mut cursor)
            .expect("SREP serialization should not fail");

        let sig_bytes: [u8; 64] = self.key_pair.sign(&self.signing_buf[..total_len]);
        let sig = Signature::from(sig_bytes);

        (srep, sig)
    }
}
