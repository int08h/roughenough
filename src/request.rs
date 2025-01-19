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

use crate::version::Version;
use crate::{Error, RtMessage, Tag, MAX_REQUEST_LENGTH, MIN_REQUEST_LENGTH, REQUEST_FRAMING_BYTES};

/// Guess which protocol the request is using and extract the client's nonce from the request
pub fn nonce_from_request(
    buf: &[u8],
    num_bytes: usize,
    expected_srv: &[u8],
) -> Result<(Vec<u8>, Version), Error> {
    if num_bytes < MIN_REQUEST_LENGTH {
        return Err(Error::RequestTooShort);
    } else if num_bytes > MAX_REQUEST_LENGTH {
        return Err(Error::RequestTooLarge);
    }

    if is_classic_request(buf) {
        nonce_from_classic_request(&buf[..num_bytes])
    } else {
        nonce_from_rfc_request(&buf[..num_bytes], expected_srv)
    }
}

/// Inspect the message in `buf`, if it doesn't start with RFC framing, we guess
/// it is a classic request
fn is_classic_request(buf: &[u8]) -> bool {
    &buf[0..8] != REQUEST_FRAMING_BYTES
}

fn nonce_from_classic_request(buf: &[u8]) -> Result<(Vec<u8>, Version), Error> {
    let msg = RtMessage::from_bytes(buf)?;
    match msg.get_field(Tag::NONC) {
        Some(nonce) => Ok((nonce.to_vec(), Version::Classic)),
        None => Err(Error::InvalidRequest),
    }
}

// This could be any VER that we support. Extract VER from request and return it.
fn nonce_from_rfc_request(buf: &[u8], expected_srv: &[u8]) -> Result<(Vec<u8>, Version), Error> {
    // first 8 bytes were RFC_REQUEST_FRAME_BYTES, [0..8]
    let mut cur = Cursor::new(&buf[8..12]);
    let reported_len = cur.read_u32::<LittleEndian>()?;
    let actual_len = (buf.len() - 12) as u32;

    if reported_len != actual_len {
        return Err(Error::LengthMismatch(reported_len, actual_len));
    }

    let msg = RtMessage::from_bytes(&buf[12..])?;

    let version = get_supported_version(&msg);
    if version.is_none() {
        return Err(Error::NoCompatibleVersion);
    }

    if let Some(request_srv) = msg.get_field(Tag::SRV) {
        if request_srv != expected_srv {
            return Err(Error::SrvMismatch);
        }
    }

    match msg.get_field(Tag::NONC) {
        Some(nonce) => Ok((nonce.to_vec(), version.unwrap())),
        None => Err(Error::InvalidRequest),
    }
}

fn get_supported_version(msg: &RtMessage) -> Option<Version> {
    const SUPPORTED_VERSIONS: &[Version] = &[Version::RfcDraft12, Version::Rfc];

    if let Some(tag_bytes) = msg.get_field(Tag::VER) {
        // Iterate the list of supplied versions, looking for the first match
        for found_ver_bytes in tag_bytes.chunks(4) {
            for ver in SUPPORTED_VERSIONS {
                if ver.wire_bytes() == found_ver_bytes {
                    return Some(*ver);
                }
            }
        }
    }
    None
}