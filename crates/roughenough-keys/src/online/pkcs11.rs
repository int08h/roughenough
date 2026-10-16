use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::EddsaParams;
use cryptoki::mechanism::eddsa::EddsaSignatureScheme::Ed25519;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use roughenough_protocol::tags::PublicKey;
use tracing::{debug, warn};

use crate::seed::{BackendError, Seed, SeedBackend};

pub struct Pkcs11Backend {
    session: Session,
    key_handle: ObjectHandle,
    public_key: [u8; 32],
}

impl Pkcs11Backend {
    pub fn new(
        lib_path: &str,
        slot_index: usize,
        auth_pin: &str,
    ) -> Result<Pkcs11Backend, BackendError> {
        debug!("Opening PKCS11 library: {}", lib_path);
        let library = Pkcs11::new(lib_path)?;
        let args = CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK);
        library.initialize(args)?;

        let info = library.get_library_info()?;
        debug!(
            "PKCS11 library: {} {}, version {}",
            info.manufacturer_id(),
            info.library_description(),
            info.library_version(),
        );

        let slot = Self::get_slot(&library, slot_index)?;
        let pin = AuthPin::new(auth_pin.into());
        let session = library.open_ro_session(slot)?;
        session.login(UserType::User, Some(&pin))?;

        let key_handle = Self::get_key_handle(&session)?;
        let public_key = Self::get_public_key(&session, key_handle)?;

        Ok(Self {
            session,
            key_handle,
            public_key,
        })
    }

    fn get_slot(library: &Pkcs11, slot_index: usize) -> Result<Slot, BackendError> {
        let slots = library.get_all_slots()?;
        debug!("Found {} PKCS11 slot(s)", slots.len());

        if slots.is_empty() {
            return Err(BackendError::NotFound(
                "No PKCS11 slots found (not plugged in?)".to_string(),
            ));
        }

        let selected_slot = *slots.get(slot_index).ok_or_else(|| {
            BackendError::NotFound(format!(
                "slot index {slot_index} is out of range ({} slots found)",
                slots.len()
            ))
        })?;

        let info = library.get_slot_info(selected_slot)?;
        debug!("Selected slot: {} {:?}", slot_index, info);

        Ok(selected_slot)
    }

    fn get_key_handle(session: &Session) -> Result<ObjectHandle, BackendError> {
        // Search for private key objects
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC_EDWARDS), // For Ed25519 keys
        ];

        let handles = session.find_objects(&template)?;
        debug!("Found {} private key(s)", handles.len());

        if handles.is_empty() {
            return Err(BackendError::NotFound(
                "No private keys found on the device".to_string(),
            ));
        }

        if handles.len() > 1 {
            warn!(
                "Found {} Ed25519 private key(s), using the first one",
                handles.len()
            );
        }

        // Use the first private key found
        Ok(handles[0])
    }

    // Read once here so a token problem fails startup instead of every later public key lookup
    fn get_public_key(
        session: &Session,
        key_handle: ObjectHandle,
    ) -> Result<[u8; 32], BackendError> {
        let attributes = session.get_attributes(key_handle, &[AttributeType::EcPoint])?;
        match attributes.first() {
            Some(Attribute::EcPoint(point)) => ed25519_from_ec_point(point),
            _ => Err(BackendError::NotSupported(
                "token returned no EC_POINT for the Ed25519 key".to_string(),
            )),
        }
    }
}

/// Tokens encode the Ed25519 EC_POINT either as a DER OCTET STRING (`04 20 || key`) or as the raw
/// 32-byte key
fn ed25519_from_ec_point(point: &[u8]) -> Result<[u8; 32], BackendError> {
    let raw = match point {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        raw if raw.len() == 32 => raw,
        other => {
            return Err(BackendError::NotSupported(format!(
                "token returned an unrecognized {}-byte EC_POINT for the Ed25519 key",
                other.len()
            )));
        }
    };
    Ok(raw.try_into().expect("length checked above"))
}

impl SeedBackend for Pkcs11Backend {
    fn store_seed(&mut self, _seed: Seed) -> Result<(), BackendError> {
        let msg = "store_seed is not supported by the SeedPkcs11 backend".to_string();
        Err(BackendError::NotSupported(msg))
    }

    fn get_seed(&self) -> Result<Seed, BackendError> {
        let msg = "get_seed is not supported by the SeedPkcs11 backend".to_string();
        Err(BackendError::NotSupported(msg))
    }

    fn sign(&mut self, data: &[u8]) -> Result<[u8; 64], BackendError> {
        debug!("signing {} bytes", data.len());

        let params = EddsaParams::new(Ed25519);
        let sig = self
            .session
            .sign(&Mechanism::Eddsa(params), self.key_handle, data)?;

        let len = sig.len();
        sig.try_into().map_err(|_| {
            BackendError::NotSupported(format!(
                "token returned a {len}-byte signature, expected 64"
            ))
        })
    }

    fn seed_len(&self) -> usize {
        32
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key_bytes())
    }

    fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key
    }
}

#[cfg(all(test, feature = "online-pkcs11"))]
mod test {
    use roughenough_protocol::util::as_hex;

    use super::*;
    use crate::online::test_util::enable_logging;

    const DEFAULT_SLOT_INDEX: usize = 0;
    const DEFAULT_PIN: &str = "123456";

    fn guess_library_path() -> &'static str {
        if cfg!(target_os = "macos") {
            "/opt/homebrew/Cellar/yubico-piv-tool/2.7.1/lib/libykcs11.2.7.1.dylib"
        } else if cfg!(target_os = "linux") {
            "/usr/lib/x86_64-linux-gnu/libykcs11.so"
        } else {
            panic!("Unsupported platform");
        }
    }

    #[test]
    fn ed25519_from_ec_point_accepts_der_and_raw() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);

        let mut der = vec![0x04, 0x20];
        der.extend_from_slice(&key);
        assert_eq!(ed25519_from_ec_point(&der).unwrap(), key);

        assert_eq!(ed25519_from_ec_point(&key).unwrap(), key);
    }

    #[test]
    fn ed25519_from_ec_point_rejects_other_lengths() {
        let key = [7u8; 32];

        let mut der_with_trailing = vec![0x04, 0x20];
        der_with_trailing.extend_from_slice(&key);
        der_with_trailing.push(0);

        let mut wrong_tag = vec![0x05, 0x20];
        wrong_tag.extend_from_slice(&key);

        for point in [
            &[][..],
            &key[..31],
            &[7u8; 33][..],
            &der_with_trailing[..],
            &wrong_tag[..],
        ] {
            assert!(
                matches!(
                    ed25519_from_ec_point(point),
                    Err(BackendError::NotSupported(_))
                ),
                "accepted a {}-byte EC_POINT",
                point.len()
            );
        }
    }

    #[test]
    #[ignore = "requires a YubiKey"]
    fn open_device() {
        enable_logging();

        let library_path = guess_library_path();
        let p = Pkcs11Backend::new(library_path, DEFAULT_SLOT_INDEX, DEFAULT_PIN).unwrap();
        println!("{}", as_hex(&p.public_key_bytes()));
    }
}
