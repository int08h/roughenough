use std::mem::size_of;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::InvalidMessageType;
use crate::wire::{FromWire, ToWire};

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
