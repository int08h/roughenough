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
        let mut to_verify = ProtocolVersion::DRAFT.dele_prefix().to_vec();
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
        let (srep, sig) = olk.make_srep(ProtocolVersion::DRAFT, &merkle_root);

        assert_eq!(srep.root(), &merkle_root);
        assert_eq!(srep.midp(), clock.epoch_seconds());
        assert_eq!(srep.radi(), 5);
        assert_eq!(srep.ver(), &ProtocolVersion::DRAFT);
        // RFC 5.2.5: VERS lists the versions the server advertises
        let expected_vers = SupportedVersions::from(ProtocolVersion::ADVERTISED.as_ref());
        assert_eq!(srep.vers(), &expected_vers);

        let verifier = Verifier::from(&olk.public_key());
        let mut to_verify = ProtocolVersion::DRAFT.srep_prefix().to_vec();
        to_verify.extend_from_slice(&srep.as_bytes().expect("SREP serialization should not fail"));
        assert!(verifier.verify(to_verify.as_ref(), sig.as_ref()));
    }

    #[test]
    fn online_key_generates_valid_srep_for_draft_versions() {
        let mut ltk = generate_ltk();
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let mut olk = ltk.make_online_key(&clock, Duration::from_secs(60));

        // A draft revision outside ADVERTISED
        let draft = ProtocolVersion::from_u32(0x8000000b).unwrap();

        let merkle_root = MerkleRoot::default();
        let (srep, sig) = olk.make_srep(draft, &merkle_root);

        assert_eq!(srep.ver(), &draft);
        // RFC 5.2.5: VERS MUST contain the version in the response's VER tag
        let expected_vers = SupportedVersions::new(&[ProtocolVersion::RFC, draft]);
        assert_eq!(srep.vers(), &expected_vers);

        // The off-list VERS keeps the SREP wire size identical to the template's
        let (baseline, _) = olk.make_srep(ProtocolVersion::DRAFT, &merkle_root);
        assert_eq!(srep.wire_size(), baseline.wire_size());

        let verifier = Verifier::from(&olk.public_key());
        let mut to_verify = draft.srep_prefix().to_vec();
        to_verify.extend_from_slice(&srep.as_bytes().expect("SREP serialization should not fail"));
        assert!(verifier.verify(to_verify.as_ref(), sig.as_ref()));
    }
}
