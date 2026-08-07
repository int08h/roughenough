use crate::error::Error;
use crate::error::Error::BufferTooSmall;
use crate::tags::fixed_tag::fixed_tag;

const SIZE: usize = 32;

fixed_tag! {
    /// The SRV tag is used by the client to indicate which long-term public key it expects to
    /// verify the response with.
    ///
    /// The value of the SRV tag is H(0xff || public_key) where public_key is the server's
    /// long-term, 32-byte Ed25519 public key and H is the first 32-bytes of SHA-512.
    SrvCommitment, SIZE, "SRV"
}

impl SrvCommitment {
    pub const HASH_PREFIX_SRV: &'static [u8] = &[0xff];
}

impl TryFrom<&[u8]> for SrvCommitment {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != SIZE {
            return Err(BufferTooSmall(SIZE, value.len()));
        }
        let buf: [u8; SIZE] = value.try_into().unwrap();
        Ok(SrvCommitment::from(buf))
    }
}

impl AsRef<[u8]> for SrvCommitment {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::ParseCursor;
    use crate::wire::{FromWire, FromWireN, ToWire};

    #[test]
    fn round_trip() {
        let srv = SrvCommitment::from([0x7fu8; SIZE]);
        let mut bytes = srv.as_bytes().unwrap();
        assert_eq!(bytes.len(), SIZE);

        let mut cursor = ParseCursor::new(&mut bytes);
        assert_eq!(SrvCommitment::from_wire(&mut cursor).unwrap(), srv);
    }

    #[test]
    fn wrong_length_is_rejected() {
        let mut bytes = vec![0u8; 64];
        for bad_len in [0usize, 31, 33, 64] {
            let mut cursor = ParseCursor::new(&mut bytes);
            assert!(matches!(
                SrvCommitment::from_wire_n(&mut cursor, bad_len),
                Err(Error::WrongTagSize(SIZE, n)) if n == bad_len
            ));
        }
    }

    #[test]
    fn try_from_wrong_length_is_rejected() {
        assert!(SrvCommitment::try_from([0u8; 31].as_slice()).is_err());
        assert!(SrvCommitment::try_from([0u8; 33].as_slice()).is_err());
        assert!(SrvCommitment::try_from([0u8; 32].as_slice()).is_ok());
    }
}
