use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::EddsaParams;
use cryptoki::mechanism::eddsa::EddsaSignatureScheme::Ed25519;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use protocol::tags::PublicKey;
use tracing::{debug, warn};

use crate::seed::{BackendError, Seed, SeedBackend};

pub struct Pkcs11Backend {
    session: Session,
    key_handle: ObjectHandle,
}

impl Pkcs11Backend {
    pub fn new(
        lib_path: &str,
        slot_index: usize,
        auth_pin: &str,
    ) -> Result<Pkcs11Backend, BackendError> {
        debug!("Opening PKCS11 library: {}", lib_path);
        let library = Pkcs11::new(lib_path)?;
        library.initialize(CInitializeArgs::OsThreads)?;

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

        Ok(Self {
            session,
            key_handle,
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

        let selected_slot = *slots
            .get(slot_index)
            .ok_or_else(|| BackendError::NotFound("slot index {} is out of range".to_string()))?;

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

        Ok(sig.try_into().unwrap())
    }

    fn seed_len(&self) -> usize {
        32
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key_bytes())
    }

    fn public_key_bytes(&self) -> [u8; 32] {
        let query_attrs = &[AttributeType::EcPoint];
        let attributes = self
            .session
            .get_attributes(self.key_handle, query_attrs)
            .unwrap();

        if let Attribute::EcPoint(point_data) = &attributes[0] {
            // For Ed25519, the EC_POINT is typically encoded as ASN.1 DER:
            // - First byte: 0x04 (uncompressed point indicator)
            // - Second byte: 0x20 length byte (32 in decimal)
            // - Next 32 bytes: the actual Ed25519 public key
            if point_data.len() >= 34 && point_data[0] == 0x04 && point_data[1] == 0x20 {
                let mut public_key_bytes = [0u8; 32];
                public_key_bytes.copy_from_slice(&point_data[2..34]);
                public_key_bytes
            }
            // Some implementations might store the raw 32-byte key directly
            else if point_data.len() == 32 {
                let mut public_key_bytes = [0u8; 32];
                public_key_bytes.copy_from_slice(point_data);
                public_key_bytes
            } else {
                panic!("key cannot be obtained from device");
            }
        } else {
            panic!("key cannot be obtained from device");
        }
    }
}

#[cfg(all(test, feature = "online-pkcs11"))]
mod test {
    use protocol::util::as_hex;

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
    #[ignore = "requires a YubiKey"]
    fn open_device() {
        enable_logging();

        let library_path = guess_library_path();
        let p = Pkcs11Backend::new(library_path, DEFAULT_SLOT_INDEX, DEFAULT_PIN).unwrap();
        println!("{}", as_hex(&p.public_key_bytes()));
    }
}
