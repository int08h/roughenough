// Copyright 2017-2021 int08h LLC
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
//! Represents the server's long-term identity.
//!

use crate::key::OnlineKey;
use crate::message::RtMessage;
use crate::sign::MsgSigner;
use crate::tag::Tag;
use crate::CERTIFICATE_CONTEXT;
use ring::digest;
use ring::digest::SHA512;
use std::fmt;
use std::fmt::Formatter;

///
/// Represents the server's long-term identity.
///
pub struct LongTermKey {
    signer: MsgSigner,
    srv_value: Vec<u8>,
}

impl LongTermKey {
    pub fn calc_srv_value(pubkey: &[u8]) -> Vec<u8> {
        let mut ctx = digest::Context::new(&SHA512);
        ctx.update(Tag::HASH_PREFIX_SRV);
        ctx.update(pubkey);
        ctx.finish().as_ref()[0..32].to_vec()
    }

    pub fn new(seed: &[u8]) -> Self {
        let signer = MsgSigner::from_seed(seed);
        let srv_value = LongTermKey::calc_srv_value(&signer.public_key_bytes());

        LongTermKey {
            signer,
            srv_value,
        }
    }

    /// Create a CERT message with a DELE containing the provided online key
    /// and a SIG of the DELE value signed by the long-term key
    pub fn make_cert(&mut self, online_key: &OnlineKey) -> RtMessage {
        let dele_bytes = online_key.make_dele().encode().unwrap();

        self.signer.update(CERTIFICATE_CONTEXT.as_bytes());
        self.signer.update(&dele_bytes);

        let dele_signature = self.signer.sign();

        let mut cert_msg = RtMessage::with_capacity(2);
        cert_msg.add_field(Tag::SIG, &dele_signature).unwrap();
        cert_msg.add_field(Tag::DELE, &dele_bytes).unwrap();

        cert_msg
    }

    /// Return the public key for the provided seed
    pub fn public_key(&self) -> Vec<u8> {
        self.signer.public_key_bytes()
    }

    /// Return the SRV tag value, which is SHA512[0:32] over (0xff || public key)
    pub fn srv_value(&self) -> &[u8] {
        self.srv_value.as_ref()
    }
}

impl fmt::Display for LongTermKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.signer)
    }
}
