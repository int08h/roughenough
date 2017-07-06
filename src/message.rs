// Copyright 2017 int08h LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::Write;
use byteorder::{LittleEndian, WriteBytesExt};

use tag::Tag;
use error::Error;

///
/// A Roughtime protocol message; a map of u32 tags to arbitrary byte-strings.
///
#[derive(Debug)]
pub struct RtMessage {
    tags: Vec<Tag>,
    values: Vec<Vec<u8>>,
}

impl RtMessage {
    /// Construct a new RtMessage
    ///
    /// ## Arguments
    ///
    /// * `num_fields` - Reserve space for this many fields.
    ///
    pub fn new(num_fields: u8) -> Self {
        RtMessage {
            tags: Vec::with_capacity(num_fields as usize),
            values: Vec::with_capacity(num_fields as usize),
        }
    }

    /// Add a field to this `RtMessage`
    ///
    /// ## Arguments
    ///
    /// * `tag` - The [`Tag`](enum.Tag.html) to add. Tags must be added in **strictly 
    ///   increasing order**, violating this will result in a 
    ///   [`Error::TagNotStrictlyIncreasing`](enum.Error.html).
    ///
    /// * `value` - Value for the tag.
    ///
    pub fn add_field(&mut self, tag: Tag, value: &[u8]) -> Result<(), Error> {
        if let Some(last_tag) = self.tags.last() {
            if tag <= *last_tag {
                return Err(Error::TagNotStrictlyIncreasing(tag));
            }
        }

        self.tags.push(tag);
        self.values.push(value.to_vec());

        Ok(())
    }

    /// Returns the number of tag/value pairs in the message
    pub fn num_fields(&self) -> u32 {
        self.tags.len() as u32
    }

    /// Encode this message into its on-the-wire representation.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
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

    /// Returns the length in bytes of this message's on-the-wire representation.
    pub fn encoded_size(&self) -> usize {
        let num_tags = self.tags.len();
        let tags_size = 4 * num_tags;
        let offsets_size = if num_tags < 2 { 0 } else { 4 * (num_tags - 1) };
        let values_size: usize = self.values.iter().map(|ref v| v.len()).sum();

        4 + tags_size + offsets_size + values_size
    }
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read};
    use byteorder::{LittleEndian, ReadBytesExt};
    use message::*;
    use tag::Tag;

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
        msg.add_field(Tag::NONC, "1234".as_bytes()).unwrap();

        assert_eq!(msg.num_fields(), 1);
        // Single tag message is 4 (num_tags) + 4 (NONC) + 4 (value)
        assert_eq!(msg.encoded_size(), 12);
    }

    #[test]
    fn two_field_message_size() {
        let mut msg = RtMessage::new(2);
        msg.add_field(Tag::NONC, "1234".as_bytes()).unwrap();
        msg.add_field(Tag::PAD, "abcd".as_bytes()).unwrap();

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

        msg.add_field(Tag::CERT, &value).unwrap();

        let mut encoded = Cursor::new(msg.encode().unwrap());

        // num tags
        assert_eq!(encoded.read_u32::<LittleEndian>().unwrap(), 1);

        // CERT tag
        let mut cert = [0u8; 4];
        encoded.read_exact(&mut cert).unwrap();
        assert_eq!(cert, Tag::CERT.wire_value());

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
        msg.add_field(Tag::DELE, &dele_value).unwrap();
        msg.add_field(Tag::MAXT, &maxt_value).unwrap();

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
        assert_eq!(encoded.read_u32::<LittleEndian>().unwrap(),
                   dele_value.len() as u32);

        // DELE tag
        let mut dele = [0u8; 4];
        encoded.read_exact(&mut dele).unwrap();
        assert_eq!(dele, Tag::DELE.wire_value());

        // MAXT tag
        let mut maxt = [0u8; 4];
        encoded.read_exact(&mut maxt).unwrap();
        assert_eq!(maxt, Tag::MAXT.wire_value());

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
