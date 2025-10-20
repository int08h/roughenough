use std::fmt::Debug;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::error::Error::{BufferTooSmall, InvalidPathLength};
use crate::util::as_hex;
use crate::wire::{FromWire, FromWireN, ToWire};

#[derive(Clone, PartialEq, Eq)]
pub struct MerklePath {
    num_paths: usize,
    data: [u8; MerklePath::capacity()],
}

impl MerklePath {
    /// RFC 5.2.4 "The PATH MUST NOT contain more than 32 hash values."
    pub const MAX_PATHS: usize = 32;
    /// Size of each path element (first 32 bytes of SHA-512) in bytes
    pub const ELEMENT_SIZE: usize = 32;

    const fn capacity() -> usize {
        Self::MAX_PATHS * Self::ELEMENT_SIZE
    }

    pub fn paths(&self) -> &[u8] {
        &self.data[..self.num_paths * Self::ELEMENT_SIZE]
    }

    /// Get the depth (number of levels) in this path
    pub fn depth(&self) -> usize {
        self.num_paths
    }

    /// Check if this path is empty (single leaf tree)
    pub fn is_empty(&self) -> bool {
        self.num_paths == 0
    }

    /// Iterator over individual path elements (each ELEMENT_SIZE bytes)
    pub fn elements(&self) -> impl Iterator<Item = &[u8]> {
        self.as_ref().chunks(Self::ELEMENT_SIZE)
    }

    /// Reset this MerklePath to an empty state
    pub fn clear(&mut self) {
        self.num_paths = 0;
    }

    /// Add a new path element to the end of this instance. Panics if this instance is already
    /// at maximum capacity (`Self::MAX_PATHS` elements).
    pub fn push_element(&mut self, element: &[u8; Self::ELEMENT_SIZE]) {
        assert!(
            self.num_paths < Self::MAX_PATHS,
            "at max capacity ({})",
            Self::MAX_PATHS
        );

        let start_idx = self.num_paths * Self::ELEMENT_SIZE;
        let end_idx = start_idx + Self::ELEMENT_SIZE;
        self.data[start_idx..end_idx].copy_from_slice(element);
        self.num_paths += 1;
    }

    /// Copy the contents of another MerklePath into this one, overwriting any existing data.
    pub fn copy_from(&mut self, other: &MerklePath) {
        self.num_paths = other.num_paths;
        let end_idx = other.num_paths * Self::ELEMENT_SIZE;
        self.data[..end_idx].copy_from_slice(&other.data[..end_idx]);
    }
}

impl Debug for MerklePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.num_paths == 0 {
            write!(f, "PATH(None)")
        } else {
            write!(
                f,
                "PATH {{ num_paths: {}, data: {} }}",
                self.num_paths,
                as_hex(self.as_ref())
            )
        }
    }
}

impl Default for MerklePath {
    fn default() -> Self {
        Self {
            num_paths: 0,
            data: [0; Self::MAX_PATHS * Self::ELEMENT_SIZE],
        }
    }
}

impl ToWire for MerklePath {
    fn wire_size(&self) -> usize {
        self.num_paths * Self::ELEMENT_SIZE
    }

    fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
        if self.num_paths == 0 {
            return Ok(());
        }

        if cursor.remaining() < self.wire_size() {
            return Err(BufferTooSmall(self.wire_size(), cursor.remaining()));
        }

        cursor.put_slice(self.as_ref());
        Ok(())
    }
}

impl FromWire for MerklePath {
    fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        MerklePath::from_wire_n(cursor, cursor.remaining())
    }
}

impl FromWireN for MerklePath {
    fn from_wire_n(cursor: &mut ParseCursor, n: usize) -> Result<Self, Error> {
        if n == 0 {
            return Ok(Self::default());
        }

        if n > Self::capacity() {
            return Err(BufferTooSmall(n, Self::capacity()));
        }

        if !n.is_multiple_of(Self::ELEMENT_SIZE) {
            return Err(InvalidPathLength(n as u32));
        }

        let mut path = MerklePath {
            num_paths: n / Self::ELEMENT_SIZE,
            data: [0; Self::capacity()],
        };

        let end = path.wire_size();
        cursor.try_copy_to_slice(&mut path.data[..end])?;

        Ok(path)
    }
}

impl AsRef<[u8]> for MerklePath {
    fn as_ref(&self) -> &[u8] {
        self.paths()
    }
}

impl TryFrom<&[u8]> for MerklePath {
    type Error = Error;

    /// Convenience conversion. This copies `data`; don't use it in hot-paths,
    /// use `push_element` instead.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let len = data.len();
        let mut copy = data.to_vec();
        let mut cursor = ParseCursor::new(&mut copy);
        MerklePath::from_wire_n(&mut cursor, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_path_depth() {
        let empty_path = MerklePath::default();
        assert_eq!(empty_path.depth(), 0);
        assert!(empty_path.is_empty());

        let data = vec![0u8; 64]; // 2 elements * 32 bytes each
        let path = MerklePath::try_from(data.as_slice()).unwrap();
        assert_eq!(path.depth(), 2);
        assert!(!path.is_empty());
    }

    #[test]
    fn merkle_path_elements() {
        let data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ];
        let path = MerklePath::try_from(data.as_slice()).unwrap();

        let elements: Vec<&[u8]> = path.elements().collect();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0], &data[0..32]);
        assert_eq!(elements[1], &data[32..64]);
    }

    #[test]
    fn merkle_path_from_wire() {
        let mut data = vec![0u8; 64]; // Valid: multiple of 32
        let mut cursor = ParseCursor::new(&mut data);
        let path = MerklePath::from_wire(&mut cursor).unwrap();
        assert_eq!(path.depth(), 2);
        assert_eq!(path.as_ref(), &data[..]);
    }

    #[test]
    fn merkle_path_invalid_length() {
        let mut data = vec![0u8; 33]; // Invalid: not multiple of 32
        let mut cursor = ParseCursor::new(&mut data);
        let result = MerklePath::from_wire(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "at max capacity")]
    fn push_element_panics_when_full() {
        let mut path = MerklePath::default();
        let element = [0u8; MerklePath::ELEMENT_SIZE];

        for _ in 0..MerklePath::MAX_PATHS {
            path.push_element(&element);
        }

        // This call should panic
        path.push_element(&element);
    }
}
