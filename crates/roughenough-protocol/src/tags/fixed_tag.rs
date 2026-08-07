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

/// Declare a fixed-size tag newtype over [`FixedTag`], generating the shared
/// trait surface (`Debug` with the wire label, `ToWire`, `FromWire`,
/// `FromWireN` with a strict size check, byte-array conversions). Tag-specific
/// conversions stay in the tag's own module.
macro_rules! fixed_tag {
    ($(#[$meta:meta])* $name:ident, $size:expr, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
        pub struct $name($crate::tags::fixed_tag::FixedTag<$size>);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!($label, "({})"), $crate::util::as_hex(self.0.as_slice()))
            }
        }

        impl $crate::wire::ToWire for $name {
            fn wire_size(&self) -> usize {
                $size
            }

            fn to_wire(
                &self,
                cursor: &mut $crate::cursor::ParseCursor,
            ) -> Result<(), $crate::error::Error> {
                self.0.to_wire(cursor)
            }
        }

        impl $crate::wire::FromWire for $name {
            fn from_wire(
                cursor: &mut $crate::cursor::ParseCursor,
            ) -> Result<Self, $crate::error::Error> {
                Ok($name(cursor.try_get_fixed()?.into()))
            }
        }

        impl $crate::wire::FromWireN for $name {
            fn from_wire_n(
                cursor: &mut $crate::cursor::ParseCursor,
                n: usize,
            ) -> Result<Self, $crate::error::Error> {
                if n != $size {
                    return Err($crate::error::Error::WrongTagSize($size, n));
                }
                <Self as $crate::wire::FromWire>::from_wire(cursor)
            }
        }

        impl From<[u8; $size]> for $name {
            fn from(bytes: [u8; $size]) -> Self {
                $name(bytes.into())
            }
        }
    };
}

pub(crate) use fixed_tag;
