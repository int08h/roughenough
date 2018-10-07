// Copyright 2017-2018 int08h LLC
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

extern crate hex;

use ring::rand;
use ring::rand::SecureRandom;
use ring::aead::AES_256_GCM;
use key::awskms::AwsKms;

pub struct EnvelopeEncryption;

impl EnvelopeEncryption {
    pub fn encrypt(kms: &AwsKms, plaintext: &[u8]) -> Vec<u8> {
        let rng = rand::SystemRandom::new();
        let mut dek = [0u8; 16];
        rng.fill(&mut dek).unwrap();
        
    }
}
