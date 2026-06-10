use Error::{
    BadNumTags, BufferTooSmall, MissingTag, OutOfBoundsOffset, UnalignedOffset, UnorderedOffset,
    UnorderedTag,
};
use pastey::paste;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::tag::Tag;
use crate::wire::ToWire;

/// Serialization-side view of a message header with a fixed, known tag set.
/// Parsing always goes through [`RawHeader`], which tolerates unknown tags as
/// the RFC requires.
pub trait Header {
    fn num_tags() -> u32;
    fn offsets(&self) -> &[u32];
    fn tags(&self) -> &[Tag];
}

fn to_wire_inner<H: Header>(header: &H, cursor: &mut ParseCursor) -> Result<(), Error> {
    if cursor.remaining() < size_of::<H>() {
        return Err(BufferTooSmall(size_of::<H>(), cursor.remaining()));
    }

    cursor.put_u32_le(H::num_tags());

    for offset in header.offsets() {
        cursor.put_u32_le(*offset);
    }

    for tag in header.tags() {
        cursor.put_slice(&tag.wire_value())
    }

    Ok(())
}

/// Maximum number of (tag, value) pairs accepted when parsing a message with an
/// open tag set. Generous compared to any message defined by the RFC.
pub const MAX_RAW_TAGS: usize = 16;

/// A message header parsed without requiring a fixed, known tag set.
///
/// RFC 5.1 requires servers to ignore unknown tags in requests, and RFC 7
/// requires clients to ignore undefined tags in responses. `RawHeader` keeps
/// tags as raw u32 values (in the same big-endian interpretation as [`Tag`])
/// instead of rejecting values this implementation does not recognize.
///
/// RFC 4.2 tag ordering is enforced on the little-endian value of each tag;
/// the ordering is strict, which also rejects duplicate tags ("A tag MUST NOT
/// appear more than once in a header").
#[derive(Debug, Clone)]
pub struct RawHeader {
    num_tags: usize,
    /// `ends[i]` is the offset one past the last byte of value i; the final
    /// entry is the total length of the message values section
    ends: [u32; MAX_RAW_TAGS],
    raw_tags: [u32; MAX_RAW_TAGS],
}

impl RawHeader {
    /// Parse a header and validate it against the remaining message length.
    /// On return the cursor is positioned at the start of the values section.
    pub fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
        let msg_len = cursor.remaining();
        Self::from_wire_n(cursor, msg_len)
    }

    /// Parse the header of a message that spans the next `msg_len` bytes of the
    /// cursor. Needed for nested messages (SREP, CERT, DELE), where the message
    /// ends before the end of the enclosing buffer.
    pub fn from_wire_n(cursor: &mut ParseCursor, msg_len: usize) -> Result<Self, Error> {
        if msg_len > cursor.remaining() {
            return Err(BufferTooSmall(msg_len, cursor.remaining()));
        }

        let start = cursor.position();
        let num_tags_field = cursor.try_get_u32_le()?;
        if num_tags_field == 0 || num_tags_field as usize > MAX_RAW_TAGS {
            return Err(BadNumTags(num_tags_field));
        }
        let num_tags = num_tags_field as usize;

        let mut header = RawHeader {
            num_tags,
            ends: [0; MAX_RAW_TAGS],
            raw_tags: [0; MAX_RAW_TAGS],
        };

        let mut prior_offset = 0;
        for idx in 0..num_tags - 1 {
            let value = cursor.try_get_u32_le()?;

            // RFC 4.2: All offsets MUST be multiples of four and placed in increasing order.
            if value % 4 != 0 {
                return Err(UnalignedOffset(idx as u32, value));
            }
            if value < prior_offset {
                return Err(UnorderedOffset(idx as u32, value));
            }

            header.ends[idx] = value;
            prior_offset = value;
        }

        let mut prior_key = 0u32;
        for idx in 0..num_tags {
            // Tags are read big-endian but ordered by their little-endian value
            let value = cursor.try_get_u32()?;
            let key = value.swap_bytes();

            if idx > 0 && key <= prior_key {
                return Err(UnorderedTag(idx as u32, value));
            }

            header.raw_tags[idx] = value;
            prior_key = key;
        }

        let header_size = cursor.position() - start;
        if msg_len < header_size {
            return Err(BufferTooSmall(header_size, msg_len));
        }

        let values_len = msg_len - header_size;
        if num_tags > 1 && header.ends[num_tags - 2] as usize > values_len {
            return Err(OutOfBoundsOffset(
                (num_tags - 2) as u32,
                header.ends[num_tags - 2],
            ));
        }
        header.ends[num_tags - 1] = values_len as u32;

        Ok(header)
    }

    pub fn num_tags(&self) -> usize {
        self.num_tags
    }

    /// Iterate `(raw_tag, value_length)` pairs in wire order. Raw tags use the
    /// same big-endian interpretation as [`Tag`] discriminants.
    pub fn entries(&self) -> impl Iterator<Item = (u32, usize)> + '_ {
        (0..self.num_tags).map(move |idx| {
            let start = if idx == 0 {
                0
            } else {
                self.ends[idx - 1] as usize
            };
            let end = self.ends[idx] as usize;
            (self.raw_tags[idx], end - start)
        })
    }
}

/// Locate the value of nested tags within a Roughtime message (without
/// framing). `path` descends into nested messages: `[Tag::CERT, Tag::DELE]`
/// returns the byte range of the DELE value within `msg`.
///
/// Signature verification must operate on the bytes as received -- a message
/// may carry tags unknown to this implementation, which re-serialization of
/// the parsed form would not reproduce. Validators use this to slice the
/// signed regions out of the original bytes.
pub fn find_value_range(msg: &mut [u8], path: &[Tag]) -> Result<std::ops::Range<usize>, Error> {
    let mut start = 0usize;
    let mut end = msg.len();

    for tag in path {
        let raw_tag = *tag as u32;
        let mut found = None;

        let mut cursor = ParseCursor::new(&mut msg[start..end]);
        let header = RawHeader::from_wire(&mut cursor)?;

        for (entry_tag, value_len) in header.entries() {
            let value_start = cursor.position();
            if entry_tag == raw_tag {
                found = Some((start + value_start, start + value_start + value_len));
                break;
            }
            cursor.set_position(value_start + value_len);
        }

        match found {
            Some((s, e)) => {
                start = s;
                end = e;
            }
            None => return Err(MissingTag(tag.name())),
        }
    }

    Ok(start..end)
}

// Frustratingly, we can't use a generic Header<const N: usize> yet because Rust does not
// currently permit a const generic to be used in a concrete expression. We can't do this yet:
//
//     struct Header<const N: usize> {
//         offsets: [u32; N - 1] // `N - 1` not allowed
//     }
//
// So for now use a macro instead.
macro_rules! make_header_n {
    ( $N:literal ) => {
        paste! {
            #[derive(Debug, Eq, PartialEq, Clone)]
            pub struct [<Header $N>] {
                num_tags: u32,
                pub(crate) offsets: [u32; $N - 1],
                pub(crate) tags: [Tag; $N],
            }

            impl Default for [<Header $N>] {
                fn default() -> Self {
                    Self {
                        num_tags: $N,
                        offsets: [0; $N - 1],
                        tags: [Tag::INVALID; $N],
                    }
                }
            }

            impl [<Header $N>] {
                const NUM_TAGS: u32 = $N;
            }

            impl ToWire for [<Header $N>] {
                fn wire_size(&self) -> usize {
                    size_of::<Self>()
                }

                fn to_wire(&self, cursor: &mut ParseCursor) -> Result<(), Error> {
                    to_wire_inner(self, cursor)
                }
            }

            impl Header for [<Header $N>] {
                fn num_tags() -> u32 {
                    Self::NUM_TAGS
                }

                fn offsets(&self) -> &[u32] {
                    &self.offsets
                }

                fn tags(&self) -> &[Tag] {
                    &self.tags
                }
            }
        }
    };
}

make_header_n!(2);
make_header_n!(3);
make_header_n!(4);
make_header_n!(5);
make_header_n!(7);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_serialization() {
        let header = Header3 {
            offsets: [88, 104],
            tags: [Tag::NONC, Tag::DELE, Tag::ROOT],
            ..Header3::default()
        };

        let mut buf = vec![0u8; header.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        header.to_wire(&mut cursor).unwrap();

        assert_eq!(
            cursor.position(),
            header.wire_size(),
            "the entire buffer should be filled"
        );

        assert_eq!(
            &buf[0..4],
            3u32.to_le_bytes(),
            "the number of pairs should be 3"
        );
        assert_eq!(
            &buf[4..8],
            88u32.to_le_bytes(),
            "the first offset should be 88"
        );
        assert_eq!(
            &buf[8..12],
            104u32.to_le_bytes(),
            "the second offset should be 104"
        );
        assert_eq!(
            &buf[12..16],
            Tag::NONC.wire_value(),
            "the first tag should be NONC"
        );
        assert_eq!(
            &buf[16..20],
            Tag::DELE.wire_value(),
            "the second tag should be DELE"
        );
        assert_eq!(
            &buf[20..24],
            Tag::ROOT.wire_value(),
            "the third tag should be ROOT"
        );

        // RawHeader parses the serialized form and derives value lengths
        // from the offsets (88, 104-88, and the remainder of the message)
        buf.resize(header.wire_size() + 104, 0);
        let mut cursor = ParseCursor::new(&mut buf);
        let raw = RawHeader::from_wire(&mut cursor).unwrap();
        let entries: Vec<(u32, usize)> = raw.entries().collect();
        assert_eq!(
            entries,
            vec![
                (Tag::NONC as u32, 88),
                (Tag::DELE as u32, 16),
                (Tag::ROOT as u32, 0),
            ]
        );
    }

    #[test]
    fn sizes() {
        assert_eq!(Header2::default().wire_size(), 16);
        assert_eq!(Header3::default().wire_size(), 24);
        assert_eq!(Header4::default().wire_size(), 32);
        assert_eq!(Header5::default().wire_size(), 40);
        assert_eq!(Header7::default().wire_size(), 56);
    }

    #[test]
    fn default_values() {
        let header = Header4::default();
        assert_eq!(header.num_tags, 4);
        assert_eq!(header.offsets, [0, 0, 0]);
        assert_eq!(header.tags, [Tag::INVALID; 4]);
    }

    #[test]
    fn unaligned_offsets() {
        let header = Header3 {
            offsets: [6, 64],
            tags: [Tag::NONC, Tag::SIG, Tag::VER],
            ..Header3::default()
        };

        let mut buf = vec![0u8; header.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        _ = header.to_wire(&mut cursor);

        let mut cursor = ParseCursor::new(&mut buf);
        let result = RawHeader::from_wire(&mut cursor);
        assert!(result.is_err(), "the first offset is not aligned");

        match result.unwrap_err() {
            UnalignedOffset(0, 6) => (), // ok, expected
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn tags_out_of_order() {
        let header = Header5 {
            offsets: [8, 16, 24, 32],
            tags: [
                Tag::SIG,
                Tag::VER,
                Tag::SRV,
                Tag::SIG, /* out of order */
                Tag::NONC,
            ],
            ..Header5::default()
        };

        let mut buf = vec![0u8; header.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        _ = header.to_wire(&mut cursor);

        let mut cursor = ParseCursor::new(&mut buf);
        let result = RawHeader::from_wire(&mut cursor);
        assert!(result.is_err(), "the second SIG tag is out of order");

        match result.unwrap_err() {
            UnorderedTag(3, _) => (), // ok, expected
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn duplicate_tags_rejected() {
        // RFC 4.2: a tag MUST NOT appear more than once in a header. The
        // strict ascending-order check rejects an equal adjacent tag.
        let header = Header3 {
            offsets: [8, 16],
            tags: [Tag::NONC, Tag::NONC, Tag::ROOT],
            ..Header3::default()
        };

        let mut buf = vec![0u8; header.wire_size() + 16];
        let mut cursor = ParseCursor::new(&mut buf);
        _ = header.to_wire(&mut cursor);

        let mut cursor = ParseCursor::new(&mut buf);
        let result = RawHeader::from_wire(&mut cursor);
        assert!(result.is_err(), "the second NONC tag is a duplicate");

        match result.unwrap_err() {
            UnorderedTag(1, _) => (), // ok, expected
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn offsets_out_of_order() {
        let header = Header4 {
            offsets: [8, 16, 12 /* out of order */],
            tags: [Tag::SIG, Tag::VER, Tag::SRV, Tag::NONC],
            ..Header4::default()
        };

        let mut buf = vec![0u8; header.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        _ = header.to_wire(&mut cursor);

        let mut cursor = ParseCursor::new(&mut buf);
        let result = RawHeader::from_wire(&mut cursor);
        assert!(result.is_err(), "the third offset is out of order");

        match result.unwrap_err() {
            UnorderedOffset(2, _) => (), // ok, expected
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn bad_num_tags() {
        // num_tags == 0
        let mut buf = 0u32.to_le_bytes().to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        match RawHeader::from_wire(&mut cursor) {
            Err(BadNumTags(0)) => (), // ok, expected
            other => panic!("unexpected result: {other:?}"),
        }

        // num_tags > MAX_RAW_TAGS
        let too_many = (MAX_RAW_TAGS + 1) as u32;
        let mut buf = too_many.to_le_bytes().to_vec();
        let mut cursor = ParseCursor::new(&mut buf);
        match RawHeader::from_wire(&mut cursor) {
            Err(BadNumTags(n)) if n == too_many => (), // ok, expected
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn offset_beyond_message_bounds() {
        let header = Header3 {
            offsets: [16, 96],
            tags: [Tag::NONC, Tag::DELE, Tag::ROOT],
            ..Header3::default()
        };

        // 56 bytes of values: the second offset (96) points past the end
        let mut buf = vec![0u8; header.wire_size() + 56];
        let mut cursor = ParseCursor::new(&mut buf);
        _ = header.to_wire(&mut cursor);

        let mut cursor = ParseCursor::new(&mut buf);
        let result = RawHeader::from_wire(&mut cursor);
        assert!(
            result.is_err(),
            "the last offset (96) is beyond the message length"
        );
        match result.unwrap_err() {
            OutOfBoundsOffset(1, 96) => (), // ok, expected
            e => panic!("unexpected error: {e:?}"),
        }
    }
}
