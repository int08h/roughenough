// Copyright 2017-2022 int08h LLC
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

use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read, Write};
use std::iter::once;
use std::string::String;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use data_encoding::{Encoding, HEXLOWER_PERMISSIVE};

use crate::error::Error;
use crate::tag::Tag;
use crate::REQUEST_FRAMING_BYTES;

const HEX: Encoding = HEXLOWER_PERMISSIVE;

///
/// A Roughtime protocol message; a map of u32 tags to arbitrary byte-strings.
///
#[derive(Debug, Clone)]
pub struct RtMessage {
    tags: Vec<Tag>,
    values: Vec<Vec<u8>>,
}

impl RtMessage {
    /// Construct a new RtMessage with the specified capacity.
    ///
    /// ## Arguments
    ///
    /// * `num_fields` - Reserve space for this many fields.
    ///
    pub fn with_capacity(num_fields: u32) -> Self {
        RtMessage {
            tags: Vec::with_capacity(num_fields as usize),
            values: Vec::with_capacity(num_fields as usize),
        }
    }

    /// Construct a new RtMessage from the on-the-wire representation in `bytes`
    ///
    /// ## Arguments
    ///
    /// * `bytes` - On-the-wire representation with any framing removed
    ///
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes_len = bytes.len();

        if bytes_len < 4 {
            return Err(Error::MessageTooShort);
        } else if bytes_len % 4 != 0 {
            return Err(Error::InvalidAlignment(bytes_len as u32));
        }

        let mut msg = Cursor::new(bytes);
        let num_tags = msg.read_u32::<LittleEndian>()?;

        match num_tags {
            0 => Ok(RtMessage::with_capacity(0)),
            1 => RtMessage::single_tag_message(bytes, &mut msg),
            2..=1024 => RtMessage::multi_tag_message(num_tags, bytes, &mut msg),
            _ => Err(Error::InvalidNumTags(num_tags)),
        }
    }

    ///
    /// Dangerous: construct a new RtMessage **without validation or error checking**.
    ///
    /// Intended _only_ for construction of deliberately bogus responses as part of [Roughtime's
    /// ecosystem](https://roughtime.googlesource.com/roughtime/+/HEAD/ECOSYSTEM.md#maintaining-a-healthy-software-ecosystem).
    ///
    pub fn new_deliberately_invalid(tags: Vec<Tag>, values: Vec<Vec<u8>>) -> Self {
        RtMessage { tags, values }
    }

    /// Internal function to create a single tag message
    fn single_tag_message(bytes: &[u8], msg: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        if bytes.len() < 8 {
            return Err(Error::MessageTooShort);
        }

        let pos = msg.position() as usize;
        msg.set_position((pos + 4) as u64);

        let mut value = Vec::new();
        msg.read_to_end(&mut value)?;

        let tag = Tag::from_wire(&bytes[pos..pos + 4])?;
        let mut rt_msg = RtMessage::with_capacity(1);
        rt_msg.add_field(tag, &value)?;

        Ok(rt_msg)
    }

    /// Internal function to create a multiple tag message
    fn multi_tag_message(
        num_tags: u32,
        bytes: &[u8],
        msg: &mut Cursor<&[u8]>,
    ) -> Result<Self, Error> {
        let bytes_len = bytes.len();
        let mut offsets = Vec::with_capacity((num_tags - 1) as usize);

        for _ in 0..num_tags - 1 {
            let offset = msg.read_u32::<LittleEndian>()?;

            if offset % 4 != 0 {
                return Err(Error::InvalidAlignment(offset));
            } else if offset > bytes_len as u32 {
                return Err(Error::InvalidOffsetValue(offset));
            }

            offsets.push(offset as usize);
        }

        let mut buf = [0; 4];
        let mut tags = Vec::with_capacity(num_tags as usize);

        for _ in 0..num_tags {
            if msg.read_exact(&mut buf).is_err() {
                return Err(Error::MessageTooShort);
            }

            let tag = Tag::from_wire(&buf)?;

            if let Some(last_tag) = tags.last() {
                if tag <= *last_tag {
                    return Err(Error::TagNotStrictlyIncreasing(tag));
                }
            }

            tags.push(tag);
        }

        // All offsets are relative to the end of the header,
        // which is our current position
        let header_end = msg.position() as usize;

        // Compute the end of the last value,
        // as an offset from the end of the header
        let msg_end = bytes.len() - header_end;

        // Create an iterator for the offset pairs of each tag value
        let start_offsets = once(&0).chain(offsets.iter());
        let end_offsets = offsets.iter().chain(once(&msg_end));
        let offset_pairs = start_offsets.zip(end_offsets);

        // The message being built
        let mut rt_msg = RtMessage::with_capacity(num_tags);

        for (tag, (value_start, value_end)) in tags.into_iter().zip(offset_pairs) {
            let start_idx = header_end + value_start;
            let end_idx = header_end + value_end;

            if end_idx > bytes_len || start_idx > end_idx {
                return Err(Error::InvalidValueLength(tag, end_idx as u32));
            }

            let value = bytes[start_idx..end_idx].to_vec();
            rt_msg.add_field(tag, &value)?;
        }

        Ok(rt_msg)
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

    /// Retrieve the value associated with `tag`, if present.
    ///
    /// ## Arguments
    ///
    /// * `tag` - The [`Tag`](enum.Tag.html) to try and retrieve.
    ///
    pub fn get_field(&self, tag: Tag) -> Option<&[u8]> {
        for (i, self_tag) in self.tags.iter().enumerate() {
            if tag == *self_tag {
                return Some(&self.values[i]);
            }
        }

        None
    }

    /// Returns the number of tag/value pairs in the message
    pub fn num_fields(&self) -> u32 {
        self.tags.len() as u32
    }

    /// Returns a slice of the tags in the message
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }

    /// Returns a slice of the values in the message
    pub fn values(&self) -> &[Vec<u8>] {
        &self.values
    }

    /// Converts the message into a `HashMap` mapping each tag to its value
    pub fn into_hash_map(self) -> HashMap<Tag, Vec<u8>> {
        self.tags.into_iter().zip(self.values).collect()
    }

    /// Encode this message into an on-the-wire representation prefixed with RFC framing.
    pub fn encode_framed(&self) -> Result<Vec<u8>, Error> {
        let encoded = self.encode()?;
        let mut frame = Vec::with_capacity(REQUEST_FRAMING_BYTES.len() + 4 + encoded.len());
        frame.write_all(REQUEST_FRAMING_BYTES)?;
        frame.write_u32::<LittleEndian>(encoded.len() as u32)?;
        frame.write_all(&encoded)?;

        Ok(frame)
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
        assert_eq!(out.len(), self.encoded_size(), "unexpected length");

        Ok(out)
    }

    /// Returns the length in bytes of this message's on-the-wire representation.
    pub fn encoded_size(&self) -> usize {
        let num_tags = self.tags.len();
        let tags_size = 4 * num_tags;
        let offsets_size = if num_tags < 2 { 0 } else { 4 * (num_tags - 1) };
        let values_size: usize = self.values.iter().map(|v| v.len()).sum();

        4 + tags_size + offsets_size + values_size
    }

    /// Calculate the length of PAD value such that the final encoded size of this message
    /// will be at least 1KB.
    pub fn calculate_padding_length(&mut self) -> usize {
        let size = self.encoded_size();
        if size >= 1024 {
            return 0;
        }

        let mut padding_needed = 1024 - size;
        if self.tags.len() == 1 {
            // If we currently only have one tag, adding a padding tag will cause
            // a 32-bit offset value to be written
            padding_needed -= 4;
        }

        padding_needed
    }

    /// Clears this message, removing all tags and values
    pub fn clear(&mut self) {
        self.tags.clear();
        self.values.clear();
    }

    pub fn to_string(&self, indent_level: usize) -> String {
        assert!(
            indent_level > 0,
            "indent level must be >= 1 (indent_level={})",
            indent_level
        );

        let indent1 = " ".repeat(2 * (indent_level - 1));
        let indent2 = " ".repeat(2 * indent_level);

        let mut result = String::from("RtMessage|");
        result.push_str(&self.num_fields().to_string());
        result.push_str("|{\n");

        for (tag, value) in self.tags.iter().zip(self.values.iter()) {
            result.push_str(&indent2);
            result.push_str(&tag.to_string());
            result.push('(');
            result.push_str(&value.len().to_string());
            result.push_str(") = ");

            if tag.is_nested() {
                let nested_msg = RtMessage::from_bytes(value).unwrap();
                result.push_str(&nested_msg.to_string(indent_level + 1))
            } else {
                result.push_str(&HEX.encode(value));
                result.push('\n');
            }
        }

        result.push_str(&indent1);
        result.push_str("}\n");

        result
    }
}

impl Display for RtMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string(1))
    }
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read};

    use byteorder::{LittleEndian, ReadBytesExt};

    use crate::message::*;
    use crate::tag::Tag;

    #[test]
    fn empty_message_size() {
        let msg = RtMessage::with_capacity(0);

        assert_eq!(msg.num_fields(), 0);
        // Empty message is 4 bytes, a single num_tags value
        assert_eq!(msg.encoded_size(), 4);
    }

    #[test]
    fn single_field_message_size() {
        let mut msg = RtMessage::with_capacity(1);
        msg.add_field(Tag::NONC, "1234".as_bytes()).unwrap();

        assert_eq!(msg.num_fields(), 1);
        // Single tag message is 4 (num_tags) + 4 (NONC) + 4 (value)
        assert_eq!(msg.encoded_size(), 12);
    }

    #[test]
    fn clear_message() {
        let mut msg = RtMessage::with_capacity(1);
        msg.add_field(Tag::NONC, "abcdefg".as_bytes()).unwrap();

        assert_eq!(msg.num_fields(), 1);
        assert_eq!(msg.tags().len(), 1);
        assert_eq!(msg.values().len(), 1);

        msg.clear();

        assert_eq!(msg.num_fields(), 0);
        assert_eq!(msg.tags().len(), 0);
        assert_eq!(msg.values().len(), 0);
    }

    #[test]
    fn two_field_message_size() {
        let mut msg = RtMessage::with_capacity(2);
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
        let msg = RtMessage::with_capacity(0);
        let mut encoded = Cursor::new(msg.encode().unwrap());

        assert_eq!(encoded.read_u32::<LittleEndian>().unwrap(), 0);
    }

    #[test]
    fn single_field_message_encoding() {
        let value = vec![b'a'; 64];
        let mut msg = RtMessage::with_capacity(1);

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

        // Round-trip single-tag message
        RtMessage::from_bytes(&msg.encode().unwrap()).unwrap();
    }

    #[test]
    fn two_field_message_encoding() {
        let dele_value = vec![b'a'; 24];
        let maxt_value = vec![b'z'; 32];

        let mut msg = RtMessage::with_capacity(2);
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
        assert_eq!(
            encoded.read_u32::<LittleEndian>().unwrap(),
            dele_value.len() as u32
        );

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

        // Round-trip multi-tag message
        RtMessage::from_bytes(&msg.encode().unwrap()).unwrap();
    }

    #[test]
    fn from_bytes_zero_tags() {
        let bytes = [0, 0, 0, 0];
        let msg = RtMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.num_fields(), 0);
    }

    #[test]
    fn retrieve_message_values() {
        let val1 = b"aabbccddeeffgg";
        let val2 = b"0987654321";

        let mut msg = RtMessage::with_capacity(2);
        msg.add_field(Tag::NONC, val1).unwrap();
        msg.add_field(Tag::MAXT, val2).unwrap();

        assert_eq!(msg.get_field(Tag::NONC), Some(val1.as_ref()));
        assert_eq!(msg.get_field(Tag::MAXT), Some(val2.as_ref()));
        assert_eq!(msg.get_field(Tag::CERT), None);
    }

    #[test]
    #[should_panic(expected = "InvalidAlignment")]
    fn from_bytes_offset_past_end_of_message() {
        let mut msg = RtMessage::with_capacity(2);
        msg.add_field(Tag::NONC, "1111".as_bytes()).unwrap();
        msg.add_field(Tag::PAD, "aaaaaaaaa".as_bytes()).unwrap();

        let mut bytes = msg.encode().unwrap();
        // set the PAD value offset to beyond end of the message
        bytes[4] = 128;

        RtMessage::from_bytes(&bytes).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidAlignment")]
    fn from_bytes_too_few_bytes_for_tags() {
        // Header says two tags (8 bytes) but truncate first tag at 2 bytes
        let bytes = &[0x02, 0, 0, 0, 4, 0, 0, 0, 0, 0];
        RtMessage::from_bytes(bytes).unwrap();
    }
}
