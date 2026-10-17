//! Decoding of keys, seeds, and other encoded values

use data_encoding::{
    BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, DecodeError, HEXLOWER_PERMISSIVE,
};
use zeroize::Zeroizing;

/// Attempt to decode `encoded_value` using hex (any case), then the base64 variants, until one
/// succeeds.
///
/// The value may be a seed, so every attempt decodes into a buffer that is zeroized on drop,
/// including attempts that fail part way through.
pub fn try_decode(encoded_value: &str) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    let input = encoded_value.as_bytes();
    let mut last_err = None;

    for encoding in [
        &HEXLOWER_PERMISSIVE,
        &BASE64URL,
        &BASE64URL_NOPAD,
        &BASE64,
        &BASE64_NOPAD,
    ] {
        let len = match encoding.decode_len(input.len()) {
            Ok(len) => len,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        let mut buf = Zeroizing::new(vec![0u8; len]);
        match encoding.decode_mut(input, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(partial) => last_err = Some(partial.error),
        }
    }

    Err(last_err.expect("at least one encoding was tried"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_mixed_case() {
        let value = try_decode(&"aB".repeat(32)).unwrap();
        assert_eq!(value.as_slice(), &[0xab; 32]);
    }

    #[test]
    fn test_decode_returns_zeroizing() {
        let _: Zeroizing<Vec<u8>> = try_decode("00").unwrap();
    }
}
