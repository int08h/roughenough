use Error::{BufferTooSmall, UnexpectedMagic};

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::UnexpectedFraming;

/// Magic value 'ROUGHTIM' for framed Requests and Responses.
pub const FRAME_MAGIC: u64 = 0x524f55474854494d;

/// Overhead of framing: 8-byte magic + 4-byte length
pub const FRAME_OVERHEAD: usize = 12;

/// All Roughtime messages will be *at least* this many bytes. A Response message is always
/// at least 404 bytes long and could be longer as the PATH and SREP values are variable-length.
/// Requests are at least 1024 bytes long.
pub const MINIMUM_FRAME_SIZE: usize = 404;

/// Implementations can serialize themselves into the Roughtime wire format
pub trait ToWire {
    fn wire_size(&self) -> usize;
    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error>;

    /// Convenience method to serialize this message into a new `Vec<u8>`.
    ///
    /// In performance-critical cases consider `to_wire` instead.
    fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; self.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        self.to_wire(&mut cursor)?;
        Ok(buf)
    }
}

/// Implementations can serialize themselves into a framed Roughtime message:
///  - 8-bytes of magic value ('ROUGHTIM')
///  - 4-bytes little endian value length
///  - Roughtime wire value
pub trait ToFrame: ToWire {
    fn frame_size(&self) -> usize {
        self.wire_size() + FRAME_OVERHEAD
    }

    fn to_frame(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        cursor.try_put_u64(FRAME_MAGIC)?;
        cursor.try_put_u32_le(self.wire_size() as u32)?;
        self.to_wire(cursor)
    }

    /// Convenience method to serialize this frame into a new `Vec<u8>`.
    ///
    /// In performance-critical cases consider `to_frame` instead.
    fn as_frame_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; self.frame_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        self.to_frame(&mut cursor)?;
        Ok(buf)
    }
}

pub trait FromWire: Sized {
    /// Parse a value occupying exactly the next `n` bytes of `cursor`.
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error>;

    /// Parse a value occupying all remaining bytes of `cursor`.
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let n = cursor.remaining();
        Self::from_wire_n(cursor, n)
    }
}

/// Implementations can deserialize themselves from a framed Roughtime message:
///  - 8-bytes of magic value ('ROUGHTIM')
///  - 4-bytes little endian value length
///  - Roughtime wire value
pub trait FromFrame: FromWire {
    fn from_frame(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let magic = cursor.try_get_u64()?;

        if magic != FRAME_MAGIC {
            return Err(UnexpectedMagic(magic));
        }

        let len = cursor.try_get_u32_le()? as usize;

        if len < MINIMUM_FRAME_SIZE || cursor.remaining() < MINIMUM_FRAME_SIZE {
            let min = std::cmp::min(len, cursor.remaining());
            return Err(UnexpectedFraming(min));
        }

        if len > cursor.remaining() {
            return Err(BufferTooSmall(len, cursor.remaining()));
        }

        // Bound parsing by the declared length: a datagram larger than its
        // frame's length field would otherwise have its trailing bytes counted
        // toward the last tag's value (RawHeader uses the cursor's remaining
        // bytes as the message length).
        cursor.truncate_remaining(len);

        FromWire::from_wire(cursor)
    }

    /// Parse a framed message from a shared byte slice.
    ///
    /// Copies `bytes` because `ParseCursor` requires a mutable buffer; hot paths that
    /// already own a mutable buffer should call `from_frame` directly.
    fn from_frame_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut buf = bytes.to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        Self::from_frame(&mut cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Request;
    use crate::response::Response;

    const RFC_REQUEST: &[u8] = include_bytes!("../testdata/rfc-request.071039e5");
    const RFC_RESPONSE: &[u8] = include_bytes!("../testdata/rfc-response.path8.index2.4c16c619");

    #[test]
    fn from_frame_bytes_matches_from_frame() {
        let mut buf = RFC_REQUEST.to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let expected = Request::from_frame(&mut cursor).unwrap();
        let parsed = Request::from_frame_bytes(RFC_REQUEST).unwrap();
        assert_eq!(parsed, expected);

        let mut buf = RFC_RESPONSE.to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        let expected = Response::from_frame(&mut cursor).unwrap();
        let parsed = Response::from_frame_bytes(RFC_RESPONSE).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn from_frame_bytes_rejects_bad_magic() {
        let mut bytes = RFC_RESPONSE.to_vec();
        bytes[0] ^= 0xff;

        let result = Response::from_frame_bytes(&bytes);
        assert!(matches!(result, Err(Error::UnexpectedMagic(_))));
    }
}
