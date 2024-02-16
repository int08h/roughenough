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

use crate::{Error, MIN_REQUEST_LENGTH, RFC_REQUEST_FRAME_BYTES, RtMessage, Tag};
use crate::version::Version;

/// Guess which protocol the request is using and extract the client's nonce from the request
pub fn nonce_from_request(buf: &[u8], num_bytes: usize) -> Result<(Vec<u8>, Version), Error> {
    if num_bytes < MIN_REQUEST_LENGTH as usize {
        return Err(Error::RequestTooShort);
    }

    match guess_protocol_version(buf) {
        Version::Classic => nonce_from_classic_request(&buf[..num_bytes]),
        Version::Rfc => nonce_from_rfc_request(&buf[..num_bytes]),
    }
}

/// Inspect the message in `buf` and guess which Roughtime protocol it corresponds to.
fn guess_protocol_version(buf: &[u8]) -> Version {
    if &buf[0..8] == RFC_REQUEST_FRAME_BYTES {
        Version::Rfc
    } else {
        Version::Classic
    }
}

fn nonce_from_classic_request(buf: &[u8]) -> Result<(Vec<u8>, Version), Error> {
    let msg = RtMessage::from_bytes(buf)?;
    match msg.get_field(Tag::NONC) {
        Some(nonce) => Ok((nonce.to_vec(), Version::Classic)),
        None => Err(Error::InvalidRequest),
    }
}

fn nonce_from_rfc_request(buf: &[u8]) -> Result<(Vec<u8>, Version), Error> {
    // first 8 bytes were RFC_REQUEST_FRAME_BYTES, [0..8]
    let mut cur = Cursor::new(&buf[8..12]);
    let reported_len = cur.read_u32::<LittleEndian>()?;
    let actual_len = (buf.len() - 12) as u32;

    if reported_len != actual_len {
        return Err(Error::LengthMismatch(reported_len, actual_len));
    }

    let msg = RtMessage::from_bytes(&buf[12..])?;

    if !has_supported_version(&msg) {
        return Err(Error::NoCompatibleVersion);
    }

    match msg.get_field(Tag::NONC) {
        Some(nonce) => Ok((nonce.to_vec(), Version::Rfc)),
        None => Err(Error::InvalidRequest),
    }
}

fn has_supported_version(msg: &RtMessage) -> bool {
    const EXPECTED_VER_BYTES: &[u8] = Version::Rfc.wire_bytes();

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
