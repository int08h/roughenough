use std::fmt::Debug;
use std::time::Duration;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::{UnexpectedOffsets, UnexpectedTags};
use crate::header::{Header, Header3};
use crate::tag::Tag;
use crate::tags::PublicKey;
use crate::wire::{FromWire, ToWire};

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
        let dele = Delegation {
            header: Header3::from_wire(cursor)?,
            public_key: PublicKey::from_wire(cursor)?,
            min_time: cursor.try_get_u64_le()?,
            max_time: cursor.try_get_u64_le()?,
        };

        if dele.header.offsets() != Self::OFFSETS {
            return Err(UnexpectedOffsets);
        }

        if dele.header.tags() != Self::TAGS {
            return Err(UnexpectedTags);
        }

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
