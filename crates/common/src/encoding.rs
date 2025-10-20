//! Encoding and decoding utilities for keys and other data

use std::io::Write;

use data_encoding::{
    BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, DecodeError, DecodeKind, HEXLOWER, HEXUPPER,
};
use protocol::tags::PublicKey;

/// Decode a public key from various encodings (hex, base64, etc).
/// Tries multiple encoding formats until one succeeds.
pub fn try_decode_key(encoded_key: &str) -> Result<PublicKey, DecodeError> {
    let key = try_decode(encoded_key)?;

    if key.len() != 32 {
        return Err(DecodeError {
            position: key.len(),
            kind: DecodeKind::Length,
        });
    }

    Ok(PublicKey::from(key.as_slice()))
}

/// Attempt to decode `encoded_value` into a `Vec<u8>` using multiple encoding formats until
/// one succeeds.
pub fn try_decode(encoded_value: &str) -> Result<Vec<u8>, DecodeError> {
    // Try all supported encodings
    let value = HEXLOWER
        .decode(encoded_value.as_bytes())
        .or_else(|_| HEXUPPER.decode(encoded_value.as_bytes()))
        .or_else(|_| BASE64URL.decode(encoded_value.as_bytes()))
        .or_else(|_| BASE64URL_NOPAD.decode(encoded_value.as_bytes()))
        .or_else(|_| BASE64.decode(encoded_value.as_bytes()))
        .or_else(|_| BASE64_NOPAD.decode(encoded_value.as_bytes()))?;

    Ok(value)
}

/// Write a hex dump of the provided data to the writer.
///
/// The output format is similar to traditional hex dump tools:
/// - 8-digit hex offset
/// - 16 bytes per line in hex (grouped by 2 bytes)
/// - ASCII representation on the right
pub fn hexdump<W: Write>(data: &[u8], writer: &mut W) -> std::io::Result<()> {
    const BYTES_PER_LINE: usize = 16;

    for (offset, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        write!(writer, "{:08x}: ", offset * BYTES_PER_LINE)?;

        for (i, byte) in chunk.iter().enumerate() {
            write!(writer, "{byte:02x}")?;
            if i % 2 == 1 {
                write!(writer, " ")?;
            }
        }

        let padding = BYTES_PER_LINE - chunk.len();
        for i in 0..padding {
            write!(writer, "  ")?;
            if (chunk.len() + i) % 2 == 1 {
                write!(writer, " ")?;
            }
        }

        write!(writer, " |")?;
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            write!(writer, "{ch}")?;
        }
        writeln!(writer, "|")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_key_hex_lower() {
        let key_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let result = try_decode_key(key_hex).unwrap();
        assert_eq!(result.as_ref(), &[0x01u8; 32]);
    }

    #[test]
    fn test_decode_key_hex_upper() {
        let key_hex = "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A";
        let result = try_decode_key(key_hex).unwrap();
        assert_eq!(result.as_ref(), &[0x0au8; 32]);
    }

    #[test]
    fn test_decode_key_base64() {
        // 32 bytes of 0x42
        let key_b64 = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";
        let result = try_decode_key(key_b64).unwrap();
        assert_eq!(result.as_ref(), &[0x42u8; 32]);
    }

    #[test]
    fn test_decode_key_base64_nopad() {
        // 32 bytes of 0x42 without padding
        let key_b64 = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
        let result = try_decode_key(key_b64).unwrap();
        assert_eq!(result.as_ref(), &[0x42u8; 32]);
    }

    #[test]
    fn test_decode_key_wrong_length() {
        let key_hex = "0101010101010101"; // Only 8 bytes
        let result = try_decode_key(key_hex);
        assert!(matches!(
            result,
            Err(DecodeError {
                position: 8,
                kind: DecodeKind::Length
            })
        ));
    }

    #[test]
    fn test_decode_key_invalid_encoding() {
        let key = "not-a-valid-key-encoding!!!";
        let result = try_decode_key(key);
        assert!(matches!(result, Err(DecodeError { .. })));
    }

    #[test]
    fn test_hexdump() {
        let data = b"Hello, World! This is a test.";
        let mut output = Vec::new();

        hexdump(data, &mut output).unwrap();
        let result = String::from_utf8(output).unwrap();

        assert!(result.contains("00000000:"));
        assert!(result.contains("4865 6c6c")); // "Hell" with space
        assert!(result.contains("|Hello, World! Th|"));
        assert!(result.contains("|is is a test.|"));
    }

    #[test]
    fn test_hexdump_short() {
        let data = b"Test";
        let mut output = Vec::new();

        hexdump(data, &mut output).unwrap();
        let result = String::from_utf8(output).unwrap();

        assert!(result.contains("00000000: 5465 7374"));
        assert!(result.contains("|Test|"));
    }
}
