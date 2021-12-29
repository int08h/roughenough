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

//!
//! Organizes requests and corresponding replies
//!

use std::net::SocketAddr;
use std::time::SystemTime;

use byteorder::{LittleEndian, WriteBytesExt};
use mio::net::UdpSocket;

use crate::{RtMessage, Tag};
use crate::config::ServerConfig;
use crate::grease::Grease;
use crate::key::{LongTermKey, OnlineKey};
use crate::merkle::MerkleTree;
use crate::version::Version;

pub struct Responder {
    version: Version,
    online_key: OnlineKey,
    long_term_public_key: String,
    cert_bytes: Vec<u8>,
    requests: Vec<(Vec<u8>, SocketAddr)>,
    merkle: MerkleTree,
    grease: Grease,
}

impl Responder {
    pub fn new(version: Version, config: &dyn ServerConfig, ltk: &mut LongTermKey) -> Responder {
        let online_key = OnlineKey::new();
        let cert_bytes = ltk.make_cert(&online_key).encode().expect("make_cert");
        let long_term_public_key = hex::encode(ltk.public_key());
        let requests = Vec::with_capacity(config.batch_size() as usize);
        let grease = Grease::new(config.fault_percentage());

        let merkle = if version == Version::Classic {
            MerkleTree::new_sha512()
        } else {
            MerkleTree::new_sha512_256()
        };

        Responder {
            version,
            online_key,
            long_term_public_key,
            cert_bytes,
            merkle,
            requests,
            grease,
        }
    }

    /// Reset internal state to prepare for a new batch of requests
    pub fn reset(&mut self) {
        self.merkle.reset();
        self.requests.clear();
    }

    /// True if there are no requests queued
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Add a request that needs to be responded to
    pub fn add_request(&mut self, nonce: Vec<u8>, src_addr: SocketAddr) {
        self.merkle.push_leaf(&nonce);
        self.requests.push((nonce, src_addr));
    }

    /// Send responses for all queued requests
    pub fn send_responses(&mut self, socket: &mut UdpSocket) {
        if self.is_empty() {
            return;
        }

        let merkle_root = self.merkle.compute_root();

        // The SREP tag is identical for each response
        let srep = self.online_key.make_srep(SystemTime::now(), &merkle_root);

        for (idx, &(ref nonce, ref src_addr)) in self.requests.iter().enumerate() {
            let paths = self.merkle.get_paths(idx);
            let resp_msg = {
                let r = self.make_response(&srep, &self.cert_bytes, &paths, idx as u32);
                if self.grease.should_add_error() {
                    self.grease.add_errors(&r)
                } else {
                    r
                }
            };

            let resp_bytes = match self.version {
                Version::Classic => resp_msg.encode().unwrap(),
                Version::Rfc => resp_msg.encode_framed().unwrap(),
            };

            let bytes_sent = socket
                .send_to(&resp_bytes, &src_addr)
                .expect("send_to failed");

            info!(
                "Responded {} {} bytes to {} for '{}..' (#{} in batch)",
                self.version,
                bytes_sent,
                src_addr,
                hex::encode(&nonce[0..4]),
                idx + 1,
            );
        }
    }

    fn make_response(
        &self,
        srep: &RtMessage,
        cert_bytes: &[u8],
        path: &[u8],
        idx: u32,
    ) -> RtMessage {
        let mut index = [0; 4];
        (&mut index as &mut [u8])
            .write_u32::<LittleEndian>(idx)
            .unwrap();

        let sig_bytes = srep.get_field(Tag::SIG).unwrap();
        let srep_bytes = srep.get_field(Tag::SREP).unwrap();

        let mut response = RtMessage::with_capacity(6);
        response.add_field(Tag::SIG, sig_bytes).unwrap();

        if self.version == Version::Rfc {
            response
                .add_field(Tag::VER, self.version.wire_bytes())
                .unwrap();
        }

        response.add_field(Tag::PATH, path).unwrap();
        response.add_field(Tag::SREP, srep_bytes).unwrap();
        response.add_field(Tag::CERT, cert_bytes).unwrap();
        response.add_field(Tag::INDX, &index).unwrap();

        response
    }

    /// Returns a reference to the long-term public key
    pub fn get_public_key(&self) -> &str {
        &self.long_term_public_key
    }

    /// Returns a reference to the on-line (delegated) key
    pub fn get_online_key(&self) -> &OnlineKey {
        &self.online_key
    }
}
