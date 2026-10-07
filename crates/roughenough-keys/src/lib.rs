// The two FFI wrapper functions in online::aws_lc_ed25519 opt in explicitly.
#![deny(unsafe_code)]

pub mod longterm;
pub mod online;
pub mod runtime;
pub mod seed;
pub mod storage;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
    use roughenough_protocol::tags::{MerkleRoot, ProtocolVersion, PublicKey, SupportedVersions};
    use roughenough_protocol::util::ClockSource;
    use roughenough_protocol::wire::ToWire;

    use crate::longterm::identity::LongTermIdentity;
    use crate::online::onlinekey::OnlineSigner;
    use crate::seed::{MemoryBackend, Seed};

    #[cfg(test)]
    mod lifecycle_tests;

    struct Verifier {
        public_key: UnparsedPublicKey<[u8; 32]>,
    }

    impl Verifier {
        pub fn new(public_key: [u8; 32]) -> Verifier {
            Verifier {
                public_key: UnparsedPublicKey::new(&ED25519, public_key),
            }
        }

        pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
            self.public_key.verify(data, signature).is_ok()
        }
    }

    impl From<&OnlineSigner> for Verifier {
        fn from(signer: &OnlineSigner) -> Verifier {
            Verifier::new(signer.public_key().as_ref().try_into().unwrap())
        }
    }

    impl From<&PublicKey> for Verifier {
        fn from(pubk: &PublicKey) -> Verifier {
            Verifier::new(pubk.as_ref().try_into().unwrap())
        }
    }

    fn generate_ltk() -> LongTermIdentity {
        let seed = MemoryBackend::from_random();
        LongTermIdentity::new(Box::new(seed))
    }

    #[test]
    #[should_panic(expected = "32 bytes")]
    fn invalid_seed_length_should_panic() {
        let _ = Seed::new(b"this won't work");
    }

    #[test]
    fn signer_verifier_roundtrip() {
        let message = b"hello world";
        let signer = OnlineSigner::from_random();
        let signature = signer.sign(message);

        let verifier = Verifier::from(&signer);
        assert!(verifier.verify(message, signature.as_ref()));
    }

    #[test]
    fn cert_is_created_correctly() {
        let mut ltk = generate_ltk();
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let olk = ltk.make_online_key(&clock, Duration::from_secs(60));

        let ltk_pubk = PublicKey::from(ltk.public_key_bytes());
        let verifier = Verifier::from(&ltk_pubk);

        let dele = olk.cert().dele();
        let sig = olk.cert().sig();
        let mut to_verify = ProtocolVersion::RFC.dele_prefix().to_vec();
        to_verify.extend_from_slice(&dele.as_bytes().expect("DELE serialization should not fail"));

        assert!(
            verifier.verify(&to_verify, sig.as_ref()),
            "LongTermKey signature on DELE should be valid"
        );
        assert_eq!(
            dele.pubk().as_ref(),
            olk.public_key().as_ref(),
            "public key in DELE should match OnlineKey"
        );
        assert_eq!(dele.mint(), now, "MINT is the now time");
        assert!(
            dele.maxt() as f64 >= now as f64 + 60.0,
            "MAXT is approximately 60 seconds in the future"
        );
    }

    #[test]
    fn online_key_generates_valid_srep_values() {
        let mut ltk = generate_ltk();
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let mut olk = ltk.make_online_key(&clock, Duration::from_secs(60));

        let merkle_root = MerkleRoot::default();
        let (srep, sig) = olk.make_srep(ProtocolVersion::RFC, &merkle_root);

        assert_eq!(srep.root(), &merkle_root);
        assert_eq!(srep.midp(), clock.epoch_seconds());
        assert_eq!(srep.radi(), 5);
        assert_eq!(srep.ver(), &ProtocolVersion::RFC);
        // RFC 5.2.5: VERS lists the versions the server advertises
        let expected_vers = SupportedVersions::from(ProtocolVersion::ADVERTISED.as_ref());
        assert_eq!(srep.vers(), &expected_vers);

        let verifier = Verifier::from(&olk.public_key());
        let mut to_verify = ProtocolVersion::RFC.srep_prefix().to_vec();
        to_verify.extend_from_slice(&srep.as_bytes().expect("SREP serialization should not fail"));
        assert!(verifier.verify(to_verify.as_ref(), sig.as_ref()));
    }

    #[test]
    fn version_one_signatures_use_rfc_context_strings() {
        let mut ltk = generate_ltk();
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let mut olk = ltk.make_online_key(&clock, Duration::from_secs(60));
        let (srep, sig) = olk.make_srep(ProtocolVersion::RFC, &MerkleRoot::default());

        let srep_bytes = srep.as_bytes().expect("SREP serialization should not fail");
        let srep_verifier = Verifier::from(&olk.public_key());
        let dele_bytes = olk
            .cert()
            .dele()
            .as_bytes()
            .expect("DELE serialization should not fail");
        let dele_verifier = Verifier::from(&PublicKey::from(ltk.public_key_bytes()));

        for (version, expected) in [
            (ProtocolVersion::RFC, true),
            (ProtocolVersion::DRAFT, false),
        ] {
            let mut to_verify = version.srep_prefix().to_vec();
            to_verify.extend_from_slice(&srep_bytes);
            assert_eq!(
                srep_verifier.verify(&to_verify, sig.as_ref()),
                expected,
                "SREP with {version:?} context string"
            );

            let mut to_verify = version.dele_prefix().to_vec();
            to_verify.extend_from_slice(&dele_bytes);
            assert_eq!(
                dele_verifier.verify(&to_verify, olk.cert().sig().as_ref()),
                expected,
                "DELE with {version:?} context string"
            );
        }
    }
}
