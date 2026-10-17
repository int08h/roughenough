/// Declare a fixed-size tag value type over `[u8; $size]`.
macro_rules! fixed_tag {
    ($(#[$meta:meta])* $name:ident, $size:expr, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $size]);

        impl $name {
            pub fn as_array(&self) -> &[u8; $size] {
                &self.0
            }
        }

        // `[u8; N]` implements `Default` only up to N = 32, and SIG is 64 bytes
        impl Default for $name {
            fn default() -> Self {
                Self([0u8; $size])
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!($label, "({})"), $crate::util::as_hex(&self.0))
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
                cursor.try_put_fixed(&self.0)
            }
        }

        impl $crate::wire::FromWire for $name {
            fn from_wire(
                cursor: &mut $crate::cursor::ParseCursor,
            ) -> Result<Self, $crate::error::Error> {
                Ok(Self(cursor.try_get_fixed()?))
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
                Self(bytes)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = $crate::error::Error;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                <[u8; $size]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| $crate::error::Error::WrongTagSize($size, bytes.len()))
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

pub(crate) use fixed_tag;
