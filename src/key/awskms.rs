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

#[cfg(feature = "kms")]
extern crate rusoto_core;
#[cfg(feature = "kms")]
extern crate rusoto_kms;

#[cfg(feature = "kms")]
use self::rusoto_core::Region;
#[cfg(feature = "kms")]
use self::rusoto_kms::{
    DecryptError, DecryptRequest, EncryptError, EncryptRequest, Kms, KmsClient,
};

use std::default::Default;
use std::error::Error;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

#[cfg(feature = "kms")]
pub struct AwsKms {
    kms_client: KmsClient,
    key_id: String,
}

#[cfg(feature = "kms")]
impl AwsKms {
    pub fn from_uri(uri: &str) -> Result<Self, DecryptError> {
        let parts: Vec<&str> = uri.split(':').collect();

        if parts.len() != 6 {
            return Err(DecryptError::Validation(
                "invalid KMS arn: too few parts".to_string(),
            ));
        }

        let region_part = parts.get(3).expect("region is missing");
        let region = match Region::from_str(region_part) {
            Ok(r) => r,
            Err(e) => return Err(DecryptError::Validation(e.description().to_string())),
        };

        Ok(AwsKms {
            kms_client: KmsClient::new(region),
            key_id: uri.to_string(),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let mut encrypt_req: EncryptRequest = Default::default();

        encrypt_req.key_id = self.key_id.clone();
        encrypt_req.plaintext = Vec::from(plaintext);

        match self.kms_client.encrypt(encrypt_req).sync() {
            Ok(result) => {
                let ciphertext = result
                    .ciphertext_blob
                    .expect("no ciphertext despite successful response");
                Ok(ciphertext)
            }
            Err(e) => Err(e),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let mut decrypt_req: DecryptRequest = Default::default();

        decrypt_req.ciphertext_blob = Vec::from(ciphertext);

        match self.kms_client.decrypt(decrypt_req).sync() {
            Ok(result) => {
                let plaintext = result
                    .plaintext
                    .expect("no plaintext despite successful response");
                Ok(plaintext)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "kms")]
impl fmt::Display for AwsKms {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.key_id)
    }
}
