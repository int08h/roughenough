use std::fmt::Write as _;

pub fn as_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(2 * data.len());

    for &byte in data {
        write!(&mut out, "{byte:02x}").unwrap();
    }

    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_as_hex() {
        assert_eq!(as_hex(&[0x01, 0x02, 0xef]), "0102ef");
    }
}
