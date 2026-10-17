// The two FFI wrapper functions in online::aws_lc_ed25519 opt in explicitly.
#![deny(unsafe_code)]

pub mod longterm;
pub mod online;
#[cfg(any(feature = "longterm-aws", feature = "longterm-gcp"))]
pub(crate) mod runtime;
pub mod seed;
pub mod storage;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use roughenough_common::clocksource::ClockSource;
    use roughenough_common::crypto::verify_with_context;
    use roughenough_protocol::tags::{MerkleRoot, ProtocolVersion, SupportedVersions};
    use roughenough_protocol::wire::ToWire;

    use crate::longterm::identity::LongTermIdentity;
    use crate::online::onlinekey::OnlineSigner;
    use crate::seed::MemoryBackend;

    #[cfg(test)]
    mod lifecycle_tests;

    fn generate_ltk() -> LongTermIdentity {
        let seed = MemoryBackend::from_random();
        LongTermIdentity::new(Box::new(seed))
    }

    #[test]
    fn signer_verifier_roundtrip() {
        let message = b"hello world";
        let signer = OnlineSigner::from_random();
        let signature = signer.sign(message);

        assert!(verify_with_context(
            signer.public_key().as_ref(),
            &[],
            message,
            signature.as_ref()
        ));
    }

    #[test]
    fn cert_is_created_correctly() {
        let mut ltk = generate_ltk();
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let olk = ltk.make_online_key(&clock, Duration::from_secs(60));

        let ltk_pubk = ltk.public_key_bytes();
        let dele = olk.cert().dele();
        let sig = olk.cert().sig();
        let dele_bytes = dele.as_bytes().expect("DELE serialization should not fail");

        assert!(
            verify_with_context(
                &ltk_pubk,
                ProtocolVersion::RFC.dele_prefix(),
                &dele_bytes,
                sig.as_ref()
            ),
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

        let srep_bytes = srep.as_bytes().expect("SREP serialization should not fail");
        assert!(verify_with_context(
            olk.public_key().as_ref(),
            ProtocolVersion::RFC.srep_prefix(),
            &srep_bytes,
            sig.as_ref()
        ));
    }

    #[test]
    fn version_one_signatures_use_rfc_context_strings() {
        let mut ltk = generate_ltk();
        let now = ClockSource::System.epoch_seconds();
        let clock = ClockSource::new_mock(now);
        let mut olk = ltk.make_online_key(&clock, Duration::from_secs(60));
        let (srep, sig) = olk.make_srep(ProtocolVersion::RFC, &MerkleRoot::default());

        let srep_bytes = srep.as_bytes().expect("SREP serialization should not fail");
        let dele_bytes = olk
            .cert()
            .dele()
            .as_bytes()
            .expect("DELE serialization should not fail");
        let ltk_pubk = ltk.public_key_bytes();

        for (version, expected) in [
            (ProtocolVersion::RFC, true),
            (ProtocolVersion::DRAFT, false),
        ] {
            assert_eq!(
                verify_with_context(
                    olk.public_key().as_ref(),
                    version.srep_prefix(),
                    &srep_bytes,
                    sig.as_ref()
                ),
                expected,
                "SREP with {version:?} context string"
            );

            assert_eq!(
                verify_with_context(
                    &ltk_pubk,
                    version.dele_prefix(),
                    &dele_bytes,
                    olk.cert().sig().as_ref()
                ),
                expected,
                "DELE with {version:?} context string"
            );
        }
    }
}
