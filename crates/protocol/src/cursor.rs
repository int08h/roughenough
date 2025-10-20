use std::mem::size_of;

use Error::BufferTooSmall;

use crate::error::Error;

/// A cursor that provides similar ergonomics to Bytes/Buf while having a simplified interface and
/// avoiding allocations.
pub struct ParseCursor<'a> {
    data: &'a mut [u8],
    position: usize,
}

impl<'a> ParseCursor<'a> {
    #[inline]
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, position: 0 }
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    #[inline]
    pub fn has_remaining(&self) -> bool {
        self.position < self.data.len()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Get an u32 in little-endian format, advancing the cursor
    #[inline]
    pub fn get_u32_le(&mut self) -> u32 {
        const SIZE: usize = size_of::<u32>();

        let bytes = &self.data[self.position..self.position + SIZE];
        let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        self.position += SIZE;
        value
    }

    /// Try to get an u32 in little-endian format, advancing the cursor
    #[inline]
    pub fn try_get_u32_le(&mut self) -> Result<u32, Error> {
        const SIZE: usize = size_of::<u32>();

        if self.remaining() < SIZE {
            return Err(BufferTooSmall(SIZE, self.remaining()));
        }

        Ok(self.get_u32_le())
    }

    /// Get an u32 in big-endian format, advancing the cursor
    #[inline]
    pub fn get_u32(&mut self) -> u32 {
        const SIZE: usize = size_of::<u32>();

        let bytes = &self.data[self.position..self.position + SIZE];
        let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        self.position += SIZE;
        value
    }

    /// Try to get an u32 in big-endian format, advancing the cursor
    #[inline]
    pub fn try_get_u32(&mut self) -> Result<u32, Error> {
        const SIZE: usize = size_of::<u32>();

        if self.remaining() < SIZE {
            return Err(BufferTooSmall(SIZE, self.remaining()));
        }

        Ok(self.get_u32())
    }

    /// Get an u64 in little-endian format, advancing the cursor
    #[inline]
    pub fn get_u64_le(&mut self) -> u64 {
        const SIZE: usize = size_of::<u64>();

        let bytes = &self.data[self.position..self.position + SIZE];
        let value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        self.position += SIZE;
        value
    }

    /// Try to get an u64 in little-endian format, advancing the cursor
    #[inline]
    pub fn try_get_u64_le(&mut self) -> Result<u64, Error> {
        const SIZE: usize = size_of::<u64>();

        if self.remaining() < SIZE {
            return Err(BufferTooSmall(SIZE, self.remaining()));
        }

        Ok(self.get_u64_le())
    }

    /// Get an u64 in big-endian format, advancing the cursor
    #[inline]
    pub fn get_u64(&mut self) -> u64 {
        const SIZE: usize = size_of::<u64>();

        let bytes = &self.data[self.position..self.position + SIZE];
        let value = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        self.position += SIZE;
        value
    }

    /// Try to get an u64 in big-endian format, advancing the cursor
    #[inline]
    pub fn try_get_u64(&mut self) -> Result<u64, Error> {
        const SIZE: usize = size_of::<u64>();

        if self.remaining() < SIZE {
            return Err(BufferTooSmall(SIZE, self.remaining()));
        }

        Ok(self.get_u64())
    }

    /// Transfer bytes from `self` into `dst`, advancing the cursor by the number of bytes written.
    #[inline]
    pub fn copy_to_slice(&mut self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.data[self.position..self.position + dst.len()]);
        self.position += dst.len();
    }

    /// Transfer bytes from `self` into `dst`, advancing the cursor by the number of bytes written.
    #[inline]
    pub fn try_copy_to_slice(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        if self.remaining() < dst.len() {
            return Err(BufferTooSmall(dst.len(), self.remaining()));
        }
        self.copy_to_slice(dst);
        Ok(())
    }

    /// Get a fixed-size array from the cursor, advancing by N bytes.
    /// This method allows the compiler to optimize bounds checks away in many cases.
    #[inline]
    pub fn get_fixed<const N: usize>(&mut self) -> [u8; N] {
        let mut result = [0u8; N];
        result.copy_from_slice(&self.data[self.position..self.position + N]);
        self.position += N;
        result
    }

    /// Try to get a fixed-size array from the cursor, advancing by N bytes.
    #[inline]
    pub fn try_get_fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        if self.remaining() < N {
            return Err(BufferTooSmall(N, self.remaining()));
        }
        Ok(self.get_fixed())
    }

    /// Put a fixed-size array into the cursor, advancing by N bytes.
    #[inline]
    pub fn put_fixed<const N: usize>(&mut self, data: &[u8; N]) {
        self.data[self.position..self.position + N].copy_from_slice(data);
        self.position += N;
    }

    /// Try to put a fixed-size array into the cursor, advancing by N bytes.
    #[inline]
    pub fn try_put_fixed<const N: usize>(&mut self, data: &[u8; N]) -> Result<(), Error> {
        if self.remaining() < N {
            return Err(BufferTooSmall(N, self.remaining()));
        }
        self.put_fixed(data);
        Ok(())
    }

    /// Transfer bytes from `src` into `self` advancing the cursor by the number of bytes written.
    ///
    /// Panics if `self` does not have enough remaining capacity to contain all of `src`.
    #[inline]
    pub fn put_slice(&mut self, src: &[u8]) {
        self.data[self.position..self.position + src.len()].copy_from_slice(src);
        self.position += src.len();
    }

    /// Transfer bytes from `src` into `self` advancing the cursor by the number of bytes written.
    ///
    /// Returns `BufferTooSmall` if `self` does not have enough remaining capacity to contain all
    /// of `src`.
    #[inline]
    pub fn try_put_slice(&mut self, src: &[u8]) -> Result<(), Error> {
        if self.remaining() < src.len() {
            return Err(BufferTooSmall(src.len(), self.remaining()));
        }
        self.put_slice(src);
        Ok(())
    }

    /// Returns a slice of the remaining data without advancing the cursor
    #[inline]
    pub fn peek(&self) -> &[u8] {
        &self.data[self.position..]
    }

    /// Write a u32 in little-endian format, advancing the cursor
    #[inline]
    pub fn put_u32_le(&mut self, value: u32) {
        let bytes = value.to_le_bytes();
        self.data[self.position..self.position + 4].copy_from_slice(&bytes);
        self.position += 4;
    }

    /// Try to write a u32 in little-endian format, advancing the cursor
    #[inline]
    pub fn try_put_u32_le(&mut self, value: u32) -> Result<(), Error> {
        const SIZE: usize = size_of::<u32>();
        if self.remaining() < SIZE {
            return Err(BufferTooSmall(SIZE, self.remaining()));
        }
        self.put_u32_le(value);
        Ok(())
    }

    /// Write a u64 in little-endian format, advancing the cursor
    #[inline]
    pub fn put_u64_le(&mut self, value: u64) {
        let bytes = value.to_le_bytes();
        self.data[self.position..self.position + 8].copy_from_slice(&bytes);
        self.position += 8;
    }

    /// Write a u64 in big-endian format, advancing the cursor
    #[inline]
    pub fn put_u64(&mut self, value: u64) {
        let bytes = value.to_be_bytes();
        self.data[self.position..self.position + 8].copy_from_slice(&bytes);
        self.position += 8;
    }

    /// Try to write a u64 in little-endian format, advancing the cursor
    #[inline]
    pub fn try_put_u64_le(&mut self, value: u64) -> Result<(), Error> {
        const SIZE: usize = size_of::<u64>();
        if self.remaining() < SIZE {
            return Err(BufferTooSmall(SIZE, self.remaining()));
        }
        self.put_u64_le(value);
        Ok(())
    }

    /// Try to write a u64 in big-endian format, advancing the cursor
    #[inline]
    pub fn try_put_u64(&mut self, value: u64) -> Result<(), Error> {
        const SIZE: usize = size_of::<u64>();
        if self.remaining() < SIZE {
            return Err(BufferTooSmall(SIZE, self.remaining()));
        }
        self.put_u64(value);
        Ok(())
    }

    /// Advance the cursor by `n` bytes
    #[inline]
    pub fn advance(&mut self, n: usize) -> Result<(), Error> {
        if self.remaining() < n {
            return Err(BufferTooSmall(n, self.remaining()));
        }
        self.position += n;
        Ok(())
    }

    /// Reset the cursor to the beginning
    #[inline]
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Get the current position
    #[inline]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Set the current position
    #[inline]
    pub fn set_position(&mut self, pos: usize) {
        self.position = pos;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cursor() {
        let mut data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut cursor = ParseCursor::new(&mut data);

        assert_eq!(cursor.remaining(), 8);
        assert_eq!(cursor.try_get_u32_le().unwrap(), 0x04030201);
        assert_eq!(cursor.remaining(), 4);
        assert_eq!(cursor.try_get_u32().unwrap(), 0x05060708);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn test_parse_cursor_bounds() {
        let mut data = [0x01, 0x02];
        let mut cursor = ParseCursor::new(&mut data);

        assert!(cursor.try_get_u32_le().is_err());
    }

    #[test]
    fn test_put_u32_le() {
        let mut data = [0u8; 8];
        {
            let mut cursor = ParseCursor::new(&mut data);
            cursor.put_u32_le(0x12345678);
            assert_eq!(cursor.position(), 4);
            cursor.put_u32_le(0xABCDEF00);
            assert_eq!(cursor.position(), 8);
        }
        assert_eq!(&data[0..4], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(&data[4..8], &[0x00, 0xEF, 0xCD, 0xAB]);
    }

    #[test]
    fn test_try_put_u32_le_bounds() {
        let mut data = [0u8; 2];
        let mut cursor = ParseCursor::new(&mut data);

        assert!(cursor.try_put_u32_le(0x12345678).is_err());
    }

    #[test]
    fn test_put_u64_le() {
        let mut data = [0u8; 16];
        {
            let mut cursor = ParseCursor::new(&mut data);
            cursor.put_u64_le(0x123456789ABCDEF0);
            assert_eq!(cursor.position(), 8);
        }
        assert_eq!(
            &data[0..8],
            &[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn test_try_put_u64_le_bounds() {
        let mut data = [0u8; 4];
        let mut cursor = ParseCursor::new(&mut data);

        assert!(cursor.try_put_u64_le(0x123456789ABCDEF0).is_err());
    }

    #[test]
    fn test_round_trip() {
        let mut data = [0u8; 16];
        let mut cursor = ParseCursor::new(&mut data);

        // Write data
        cursor.put_u32_le(0x12345678);
        cursor.put_u64_le(0x9ABCDEF012345678);

        // Reset and read back
        cursor.reset();
        assert_eq!(cursor.get_u32_le(), 0x12345678);
        assert_eq!(cursor.get_u64_le(), 0x9ABCDEF012345678);
    }
}
