use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::{FromWire, ToWire};

/// A generic fixed-size tag type that eliminates some runtime bounds checking for tags with a
/// compile-time known size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedTag<const N: usize>([u8; N]);

impl<const N: usize> FixedTag<N> {
    #[inline]
    pub fn new(data: [u8; N]) -> Self {
        Self(data)
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != N {
            return Err(Error::WrongTagSize(N, slice.len()));
        }
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        Ok(Self(data))
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Default for FixedTag<N> {
    #[inline]
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> From<[u8; N]> for FixedTag<N> {
    #[inline]
    fn from(data: [u8; N]) -> Self {
        Self(data)
    }
}

impl<const N: usize> From<&[u8; N]> for FixedTag<N> {
    #[inline]
    fn from(data: &[u8; N]) -> Self {
        Self(*data)
    }
}

impl<const N: usize> AsRef<[u8]> for FixedTag<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> ToWire for FixedTag<N> {
    #[inline]
    fn wire_size(&self) -> usize {
        N
    }

    #[inline]
    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        cursor.try_put_fixed(&self.0)
    }
}

impl<const N: usize> FromWire for FixedTag<N> {
    #[inline]
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        Ok(Self(cursor.try_get_fixed()?))
    }
}
