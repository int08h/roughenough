extern crate byteorder;

use std::io::Write;
use byteorder::{LittleEndian, WriteBytesExt};

#[derive(Debug)]
pub enum RtError {
    TagNotStrictlyIncreasing(RtTag),
    EncodingFailure(std::io::Error),
}

impl From<std::io::Error> for RtError {
    fn from(err: std::io::Error) -> Self {
        RtError::EncodingFailure(err)
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RtTag {
    CERT,
    DELE,
    INDX,
    MAXT,
    MIDP,
    MINT,
    NONC,
    PAD,
    PATH,
    PUBK,
    RADI,
    ROOT,
    SIG,
    SREP,
}

static PAD_VALUE: [u8; 4] = [b'P', b'A', b'D', 0x00];
static SIG_VALUE: [u8; 4] = [b'S', b'I', b'G', 0xff];

impl RtTag {
    pub fn wire_value(&self) -> &'static [u8] {
        match *self {
            RtTag::CERT => "CERT".as_bytes(),
            RtTag::DELE => "DELE".as_bytes(),
            RtTag::INDX => "INDX".as_bytes(),
            RtTag::MAXT => "MAXT".as_bytes(),
            RtTag::MIDP => "MIDP".as_bytes(),
            RtTag::MINT => "MINT".as_bytes(),
            RtTag::NONC => "NONC".as_bytes(),
            RtTag::PAD =>  PAD_VALUE.as_ref(),
            RtTag::PATH => "PATH".as_bytes(),
            RtTag::PUBK => "PUBK".as_bytes(),
            RtTag::RADI => "RADI".as_bytes(),
            RtTag::ROOT => "ROOT".as_bytes(),
            RtTag::SIG => SIG_VALUE.as_ref(),
            RtTag::SREP => "SREP".as_bytes(),
        }
    }
}

#[derive(Debug)]
pub struct RtMessage<'a> {
    tags: Vec<RtTag>,
    values: Vec<&'a [u8]>,
}

impl<'a> RtMessage<'a> {
    pub fn new(num_fields: u8) -> Self {
        RtMessage {
            tags: Vec::with_capacity(num_fields as usize),
            values: Vec::with_capacity(num_fields as usize)
        }
    }

    pub fn add_field(&mut self, tag: RtTag, value: &'a [u8]) -> Result<(), RtError> {
        if let Some(last_tag) = self.tags.last() {
            if tag <= *last_tag {
                return Err(RtError::TagNotStrictlyIncreasing(tag));
            }
        }

        self.tags.push(tag);
        self.values.push(value);

        Ok(())
    }

    pub fn num_fields(&self) -> u32 {
        self.tags.len() as u32
    }

    pub fn encode(&self) -> Result<Vec<u8>, RtError> {
        let num_tags = self.tags.len();
        let mut out = Vec::with_capacity(self.encoded_size());

        // number of tags
        out.write_u32::<LittleEndian>(num_tags as u32)?;

        // offset(s) to values, IFF there are two or more tags
        if num_tags > 1 {
            let mut offset_sum = self.values[0].len();

            for val in &self.values[1..] {
                out.write_u32::<LittleEndian>(offset_sum as u32)?;
                offset_sum += val.len();
            }
        }

        // write tags 
        for tag in &self.tags {
            out.write_all(tag.wire_value())?;
        }

        // write values
        for value in &self.values {
            out.write_all(value)?;
        }

        // check we wrote exactly what we expected
        assert!(out.len() == self.encoded_size(), "unexpected length");

        Ok(out)
    }

    fn encoded_size(&self) -> usize {
        let num_tags = self.tags.len();
        let tags_size = 4 * num_tags;
        let offsets_size = if num_tags < 2 { 0 } else { 4 * (num_tags - 1) };
        let values_size: usize = self.values.iter().map(|&v| v.len()).sum();

        4 + tags_size + offsets_size + values_size
    }
}

#[cfg(not(test))]
fn main() {
    let mut msg = RtMessage::new(3);

    msg.add_field(RtTag::CERT, "abcd".as_bytes()).unwrap();
    msg.add_field(RtTag::NONC, "1234".as_bytes()).unwrap();

    println!("msg {:?}", msg.encode());
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read};
    use byteorder::{LittleEndian, ReadBytesExt};
    use super::*;

    #[test]
    fn empty_message_size() {
        let msg = RtMessage::new(0);

        assert_eq!(msg.num_fields(), 0);
        // Empty message is 4 bytes, a single num_tags value
        assert_eq!(msg.encoded_size(), 4);
    }

    #[test]
    fn single_field_message_size() {
        let mut msg = RtMessage::new(1);
        msg.add_field(RtTag::NONC, "1234".as_bytes()).unwrap();

        assert_eq!(msg.num_fields(), 1);
        // Single tag message is 4 (num_tags) + 4 (NONC) + 4 (value)
        assert_eq!(msg.encoded_size(), 12);
    }

    #[test]
    fn two_field_message_size() {
        let mut msg = RtMessage::new(2);
        msg.add_field(RtTag::NONC, "1234".as_bytes()).unwrap();
        msg.add_field(RtTag::PAD, "abcd".as_bytes()).unwrap();

        assert_eq!(msg.num_fields(), 2);
		// Two tag message
		//   4 num_tags
		//   8 (NONC, PAD) tags
		//   4 PAD offset
		//   8 values
        assert_eq!(msg.encoded_size(), 24);
    }

    #[test]
    fn empty_message_encoding() {
        let msg = RtMessage::new(0);
        let mut encoded = Cursor::new(msg.encode().unwrap());

        assert_eq!(encoded.read_u32::<LittleEndian>().unwrap(), 0);
    }

    #[test]
    fn single_field_message_encoding() {
        let value = vec![b'a'; 64];
        let mut msg = RtMessage::new(1);

        msg.add_field(RtTag::CERT, &value).unwrap();

        let mut encoded = Cursor::new(msg.encode().unwrap());

        // num tags
        assert_eq!(encoded.read_u32::<LittleEndian>().unwrap(), 1);

        // CERT tag
        let mut cert = [0u8; 4];
        encoded.read_exact(&mut cert).unwrap();
        assert_eq!(cert, RtTag::CERT.wire_value());

        // CERT value
        let mut read_val = vec![0u8; 64];
        encoded.read_exact(&mut read_val).unwrap();
        assert_eq!(value, read_val);

        // Entire message was read
        assert_eq!(encoded.position(), 72);
    }

    #[test]
    fn two_field_message_encoding() {
        let dele_value = vec![b'a'; 24];
        let maxt_value = vec![b'z'; 32];

        let mut msg = RtMessage::new(2);
        msg.add_field(RtTag::DELE, &dele_value).unwrap();
        msg.add_field(RtTag::MAXT, &maxt_value).unwrap();

        let foo = msg.encode().unwrap();

        let mut encoded = Cursor::new(msg.encode().unwrap());
		// Wire encoding
		//   4 num_tags
		//   8 (DELE, MAXT) tags
		//   4 MAXT offset
		//  24 DELE value
		//  32 MAXT value

        // num tags
        assert_eq!(encoded.read_u32::<LittleEndian>().unwrap(), 2);

        // Offset past DELE value to start of MAXT value
        assert_eq!(encoded.read_u32::<LittleEndian>().unwrap(), dele_value.len() as u32);

        // DELE tag
        let mut dele = [0u8; 4];
        encoded.read_exact(&mut dele).unwrap();
        assert_eq!(dele, RtTag::DELE.wire_value());
        
        // MAXT tag
        let mut maxt = [0u8; 4];
        encoded.read_exact(&mut maxt).unwrap();
        assert_eq!(maxt, RtTag::MAXT.wire_value());

        // DELE value
        let mut read_dele_val = vec![0u8; 24];
        encoded.read_exact(&mut read_dele_val).unwrap();
        assert_eq!(dele_value, read_dele_val);
        
        // MAXT value
        let mut read_maxt_val = vec![0u8; 32];
        encoded.read_exact(&mut read_maxt_val).unwrap();
        assert_eq!(maxt_value, read_maxt_val);

        // Everything was read
        assert_eq!(encoded.position() as usize, msg.encoded_size());
    }
}


