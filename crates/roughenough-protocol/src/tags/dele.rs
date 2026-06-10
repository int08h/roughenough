use std::fmt::Debug;
use std::time::Duration;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::{MissingTag, WrongTagSize};
use crate::header::{Header3, RawHeader};
use crate::tag::Tag;
use crate::tags::PublicKey;
use crate::wire::{FromWire, FromWireN, ToWire};

#[repr(C)]
#[derive(PartialEq, Eq, Clone)]
pub struct Delegation {
    header: Header3,
    public_key: PublicKey,
    min_time: u64,
    max_time: u64,
}

impl Delegation {
    const MINT_OFFSET: u32 = size_of::<PublicKey>() as u32;
    const MAXT_OFFSET: u32 = Self::MINT_OFFSET + size_of::<u64>() as u32;
    const OFFSETS: [u32; 2] = [Self::MINT_OFFSET, Self::MAXT_OFFSET];
    const TAGS: [Tag; 3] = [Tag::PUBK, Tag::MINT, Tag::MAXT];

    pub fn new(public_key: PublicKey, now_epoch_sec: u64, validity: Duration) -> Self {
        Self {
            public_key,
            min_time: now_epoch_sec,
            max_time: now_epoch_sec.saturating_add(validity.as_secs()),
            ..Delegation::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn header(&self) -> &Header3 {
        &self.header
    }

    pub fn pubk(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn mint(&self) -> u64 {
        self.min_time
    }

    pub fn maxt(&self) -> u64 {
        self.max_time
    }

    pub fn set_pubk(&mut self, pubk: PublicKey) {
        self.public_key = pubk;
    }

    pub fn set_mint(&mut self, mint: u64) {
        self.min_time = mint;
    }

    pub fn set_maxt(&mut self, maxt: u64) {
        self.max_time = maxt;
    }
}

impl Default for Delegation {
    fn default() -> Self {
        let mut dele = Self {
            header: Header3::default(),
            public_key: PublicKey::default(),
            min_time: 0,
            max_time: 0,
        };

        dele.header.offsets = Self::OFFSETS;
        dele.header.tags = Self::TAGS;
        dele
    }
}

impl FromWire for Delegation {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let msg_len = cursor.remaining();
        Self::from_wire_n(cursor, msg_len)
    }
}

impl FromWireN for Delegation {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error> {
        const RAW_PUBK: u32 = Tag::PUBK as u32;
        const RAW_MINT: u32 = Tag::MINT as u32;
        const RAW_MAXT: u32 = Tag::MAXT as u32;

        let header = RawHeader::from_wire_n(cursor, n)?;

        let mut public_key: Option<PublicKey> = None;
        let mut min_time: Option<u64> = None;
        let mut max_time: Option<u64> = None;

        for (raw_tag, value_len) in header.entries() {
            let value_start = cursor.position();

            match raw_tag {
                RAW_PUBK => {
                    if value_len != size_of::<PublicKey>() {
                        return Err(WrongTagSize(size_of::<PublicKey>(), value_len));
                    }
                    public_key = Some(PublicKey::from_wire(cursor)?);
                }
                RAW_MINT => {
                    if value_len != size_of::<u64>() {
                        return Err(WrongTagSize(size_of::<u64>(), value_len));
                    }
                    min_time = Some(cursor.try_get_u64_le()?);
                }
                RAW_MAXT => {
                    if value_len != size_of::<u64>() {
                        return Err(WrongTagSize(size_of::<u64>(), value_len));
                    }
                    max_time = Some(cursor.try_get_u64_le()?);
                }
                // RFC 7: clients MUST properly ignore undefined tags
                _ => {}
            }

            cursor.set_position(value_start + value_len);
        }

        let mut dele = Delegation::default();
        dele.set_pubk(public_key.ok_or(MissingTag("PUBK"))?);
        dele.set_mint(min_time.ok_or(MissingTag("MINT"))?);
        dele.set_maxt(max_time.ok_or(MissingTag("MAXT"))?);

        Ok(dele)
    }
}

impl ToWire for Delegation {
    fn wire_size(&self) -> usize {
        size_of::<Self>()
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        self.header.to_wire(cursor)?;
        self.public_key.to_wire(cursor)?;
        cursor.put_u64_le(self.min_time);
        cursor.put_u64_le(self.max_time);
        Ok(())
    }
}

impl Debug for Delegation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DELE")
            .field("header", &self.header)
            .field("public_key", &self.public_key)
            .field("min_time", &self.min_time)
            .field("max_time", &self.max_time)
            .finish()
    }
}
