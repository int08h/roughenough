use Error::{
    BufferTooSmall, MismatchedNumTags, OutOfBoundsOffset, UnalignedOffset, UnorderedOffset,
    UnorderedTag,
};
use pastey::paste;

use crate::cursor::ParseCursor;
use crate::error::Error;
use crate::tag::Tag;
use crate::wire::{FromWire, ToWire};

pub trait Header {
    fn num_tags() -> u32;
    fn offsets(&self) -> &[u32];
    fn tags(&self) -> &[Tag];

    fn set_offset(&mut self, idx: usize, offset: u32);
    fn set_tag(&mut self, idx: usize, tag: Tag);

    fn check_offset_bounds(&self, total_len: usize) -> Result<(), Error>;
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

fn from_wire_inner<H: Header + Default>(cursor: &mut ParseCursor) -> Result<H, Error> {
    if cursor.remaining() < size_of::<H>() {
        return Err(BufferTooSmall(size_of::<H>(), cursor.remaining()));
    }

    let mut header = H::default();

    let read_num_tags = cursor.try_get_u32_le()?;
    if H::num_tags() != read_num_tags {
        return Err(MismatchedNumTags(H::num_tags(), read_num_tags));
    }

    let mut prior_offset = 0;
    for idx in 0..(H::num_tags() - 1) {
        let value = cursor.try_get_u32_le()?;

        // RFC 4.2: All offsets MUST be multiples of four and placed in increasing order.
        if value % 4 != 0 {
            return Err(UnalignedOffset(idx, value));
        }

        if value < prior_offset {
            return Err(UnorderedOffset(idx, value));
        }

        header.set_offset(idx as usize, value);
        prior_offset = value;
    }

    let mut prior_tag = Tag::INVALID;
    for idx in 0..H::num_tags() {
        // Tags themselves are read big-endian even though tag ordering is based on
        // their little-endian value.
        let value = cursor.try_get_u32()?;
        let tag = Tag::try_from(value)?;

        // RFC 4.2: Tags MUST be listed in the same order as the offsets of their values
        // and be sorted in ascending order by numeric value.
        if tag < prior_tag {
            return Err(UnorderedTag(idx, value));
        }

        header.set_tag(idx as usize, tag);
        prior_tag = tag;
    }

    Ok(header)
}

fn check_offset_bounds_inner<H: Header>(header: &H, total_len: usize) -> Result<(), Error> {
    for (idx, &offset) in header.offsets().iter().enumerate() {
        if offset > total_len as u32 {
            return Err(OutOfBoundsOffset(idx as u32, offset));
        }
    }

    Ok(())
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

            impl FromWire for [<Header $N>] {
                fn from_wire(cursor: &mut ParseCursor) -> Result<Self, Error> {
                    from_wire_inner(cursor)
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

                fn check_offset_bounds(&self, total_len: usize) -> Result<(), Error> {
                    check_offset_bounds_inner(self, total_len)
                }

                fn set_offset(&mut self, idx: usize, offset: u32) {
                    self.offsets[idx] = offset;
                }

                fn set_tag(&mut self, idx: usize, tag: Tag) {
                    self.tags[idx] = tag;
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

        let mut cursor = ParseCursor::new(&mut buf);
        let decoded = Header3::from_wire(&mut cursor).unwrap();
        assert_eq!(
            decoded, header,
            "the decoded header should match the original"
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
        let result = Header3::from_wire(&mut cursor);
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
        let result = Header5::from_wire(&mut cursor);
        assert!(result.is_err(), "the second SIG tag is out of order");

        match result.unwrap_err() {
            UnorderedTag(3, _) => (), // ok, expected
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
        let result = Header4::from_wire(&mut cursor);
        assert!(result.is_err(), "the third offset is out of order");

        match result.unwrap_err() {
            UnorderedOffset(2, _) => (), // ok, expected
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn mismatched_num_tags() {
        let header = Header3 {
            offsets: [8, 16],
            tags: [Tag::SIG, Tag::VER, Tag::SRV],
            ..Header3::default()
        };

        let mut buf = vec![0u8; header.wire_size()];
        let mut cursor = ParseCursor::new(&mut buf);
        _ = header.to_wire(&mut cursor);

        let mut cursor = ParseCursor::new(&mut buf);
        let result = Header2::from_wire(&mut cursor);
        assert!(result.is_err(), "we wrote a Header3 but read a Header2");

        match result.unwrap_err() {
            MismatchedNumTags(2, 3) => (),
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn offset_bounds_check() {
        let header = Header3 {
            offsets: [16, 96],
            tags: [Tag::SIG, Tag::VER, Tag::SRV],
            ..Header3::default()
        };

        // This will pass, the last offset is within the total length
        assert!(header.check_offset_bounds(100).is_ok());

        // This will fail, the last offset is not within the total length
        let result = header.check_offset_bounds(56);
        assert!(
            result.is_err(),
            "the last offset (96) is beyond the total length"
        );
        match result.unwrap_err() {
            OutOfBoundsOffset(1, 96) => (), // ok, expected
            e => panic!("unexpected error: {e:?}"),
        }
    }
}
