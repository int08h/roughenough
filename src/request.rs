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

//! Extract nonces from requests

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::{Error, MIN_REQUEST_LENGTH, REQUEST_FRAME_BYTES, RtMessage, Tag};
use crate::version::Version;

pub fn nonce_from_request(buf: &[u8], num_bytes: usize) -> Result<Vec<u8>, Error> {
    if num_bytes < MIN_REQUEST_LENGTH as usize {
        return Err(Error::RequestTooShort);
    }

    if &buf[0..8] != REQUEST_FRAME_BYTES {
        return Err(Error::InvalidRequest);
    }

    extract_nonce(&buf[8..num_bytes])
}

fn extract_nonce(buf: &[u8]) -> Result<Vec<u8>, Error> {
    const LENGTH_FIELD_BYTES: usize = 4;

    let mut cur = Cursor::new(&buf[0..4]);
    let reported_len = cur.read_u32::<LittleEndian>()?;
    let actual_len = (buf.len() - LENGTH_FIELD_BYTES) as u32;

    if reported_len != actual_len {
        return Err(Error::LengthMismatch(reported_len, actual_len));
    }

    let msg = RtMessage::from_bytes(&buf[4..])?;

    if !has_supported_version(&msg) {
        return Err(Error::NoCompatibleVersion);
    }

    match msg.get_field(Tag::NONC) {
        Some(nonce) => Ok(nonce.to_vec()),
        None => Err(Error::InvalidRequest),
    }
}

fn has_supported_version(msg: &RtMessage) -> bool {
    const EXPECTED_VER_BYTES: &[u8] = Version::RfcDraft8.wire_bytes();

    if let Some(tag_bytes) = msg.get_field(Tag::VER) {
        // Iterate the list of supplied versions, looking for a match
        for found_ver_bytes in tag_bytes.chunks(4) {
            if found_ver_bytes == EXPECTED_VER_BYTES {
                return true;
            }
        }
    }

    false
}
