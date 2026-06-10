//! Raw message builders for tests.
//!
//! These helpers intentionally bypass the typed message structs so tests can
//! construct and mutate messages containing tags this implementation does not
//! define (e.g. grease tags). They are available to other crates' tests via
//! the `test-utils` feature; they are not part of the public API.

use std::ops::Range;

/// Byte layout of a raw message: value start offsets (relative to the values
/// section), the positions of the tags and values sections, and the total
/// length of the values section.
struct Layout {
    starts: Vec<usize>,
    tags_start: usize,
    values_start: usize,
    values_len: usize,
}

fn layout(msg: &[u8]) -> Layout {
    let num = u32::from_le_bytes(msg[0..4].try_into().unwrap()) as usize;
    let mut starts = vec![0usize];
    for i in 0..num - 1 {
        let off = u32::from_le_bytes(msg[4 + i * 4..8 + i * 4].try_into().unwrap());
        starts.push(off as usize);
    }
    let tags_start = 4 + (num - 1) * 4;
    let values_start = tags_start + num * 4;
    let values_len = msg.len() - values_start;

    Layout {
        starts,
        tags_start,
        values_start,
        values_len,
    }
}

impl Layout {
    fn num(&self) -> usize {
        self.starts.len()
    }

    fn tag(&self, msg: &[u8], i: usize) -> [u8; 4] {
        msg[self.tags_start + i * 4..self.tags_start + i * 4 + 4]
            .try_into()
            .unwrap()
    }

    /// Range of value `i` within the whole message
    fn value_range(&self, i: usize) -> Range<usize> {
        let start = self.starts[i];
        let end = if i + 1 < self.num() {
            self.starts[i + 1]
        } else {
            self.values_len
        };
        self.values_start + start..self.values_start + end
    }
}

/// Split a raw message (no framing) into its (tag, value) entries
pub fn parse_entries(msg: &[u8]) -> Vec<([u8; 4], Vec<u8>)> {
    let layout = layout(msg);
    (0..layout.num())
        .map(|i| (layout.tag(msg, i), msg[layout.value_range(i)].to_vec()))
        .collect()
}

/// Build a raw Roughtime message from (tag, value) entries. Entries must
/// already be sorted by the little-endian value of their tags.
pub fn build_msg(entries: &[([u8; 4], Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    let mut acc = 0u32;
    for (_, value) in &entries[..entries.len() - 1] {
        acc += value.len() as u32;
        out.extend_from_slice(&acc.to_le_bytes());
    }
    for (tag, _) in entries {
        out.extend_from_slice(tag);
    }
    for (_, value) in entries {
        out.extend_from_slice(value);
    }
    out
}

/// Wrap a raw message in ROUGHTIM framing
pub fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ROUGHTIM");
    out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    out.extend_from_slice(msg);
    out
}

/// Re-encode a raw message with one extra (tag, value) entry spliced in at
/// its sorted position
pub fn insert_tag(msg: &[u8], new_tag: [u8; 4], new_value: &[u8]) -> Vec<u8> {
    let mut entries = parse_entries(msg);

    // Tags sort by the little-endian interpretation of their bytes
    let key = |t: &[u8; 4]| u32::from_le_bytes(*t);
    let pos = entries
        .iter()
        .position(|(t, _)| key(t) > key(&new_tag))
        .unwrap_or(entries.len());
    entries.insert(pos, (new_tag, new_value.to_vec()));

    build_msg(&entries)
}

/// Rebuild a raw message replacing the value of `tag` with `new_value`
pub fn replace_value(msg: &[u8], tag: [u8; 4], new_value: &[u8]) -> Vec<u8> {
    let mut entries = parse_entries(msg);
    let entry = entries
        .iter_mut()
        .find(|(t, _)| *t == tag)
        .expect("tag not found");
    entry.1 = new_value.to_vec();

    build_msg(&entries)
}

/// Locate the value range of `tag` in a raw message (no framing)
pub fn value_range(msg: &[u8], tag: [u8; 4]) -> Range<usize> {
    let layout = layout(msg);
    for i in 0..layout.num() {
        if layout.tag(msg, i) == tag {
            return layout.value_range(i);
        }
    }
    panic!("tag not found");
}
