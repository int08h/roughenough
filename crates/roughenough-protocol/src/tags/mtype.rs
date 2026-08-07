use std::mem::size_of;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::InvalidMessageType;
use crate::wire::{FromWire, FromWireN, ToWire};

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    Request = 0x00000000,
    Response = 0x00000001,
    Invalid = 0xffffffff,
}

impl ToWire for MessageType {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        let value = *self as u32;
        cursor.put_u32_le(value);
        Ok(())
    }
}

impl FromWire for MessageType {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let value = cursor.try_get_u32_le()?;
        match value {
            0x00000000 => Ok(MessageType::Request),
            0x00000001 => Ok(MessageType::Response),
            _ => Err(InvalidMessageType(value)),
        }
    }
}

impl FromWireN for MessageType {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error> {
        if n != size_of::<Self>() {
            return Err(Error::WrongTagSize(size_of::<Self>(), n));
        }
        Self::from_wire(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for msg_type in [MessageType::Request, MessageType::Response] {
            let mut bytes = msg_type.as_bytes().unwrap();
            let mut cursor = ParseCursor::new(&mut bytes);
            assert_eq!(MessageType::from_wire(&mut cursor).unwrap(), msg_type);
        }
    }

    #[test]
    fn undefined_values_are_rejected() {
        // Only 0 (request) and 1 (response) are defined; 0xffffffff is the
        // Invalid sentinel and must not parse either
        for bad in [2u32, 0x8000_0000, 0xffff_ffff] {
            let mut bytes = bad.to_le_bytes().to_vec();
            let mut cursor = ParseCursor::new(&mut bytes);
            assert!(matches!(
                MessageType::from_wire(&mut cursor),
                Err(InvalidMessageType(v)) if v == bad
            ));
        }
    }

    #[test]
    fn wrong_length_is_rejected() {
        let mut bytes = vec![0u8; 8];
        for bad_len in [0usize, 3, 5, 8] {
            let mut cursor = ParseCursor::new(&mut bytes);
            assert!(matches!(
                MessageType::from_wire_n(&mut cursor, bad_len),
                Err(Error::WrongTagSize(4, n)) if n == bad_len
            ));
        }
    }
}
