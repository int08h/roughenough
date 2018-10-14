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
extern crate log;

#[cfg(feature = "awskms")]
pub mod inner {
    extern crate rusoto_core;
    extern crate rusoto_kms;

    use std::default::Default;
    use std::error::Error;
    use std::fmt;
    use std::fmt::Formatter;
    use std::str::FromStr;

    use self::rusoto_core::Region;
    use self::rusoto_kms::{DecryptRequest, EncryptRequest, Kms, KmsClient};
    use kms::{EncryptedDEK, KmsError, KmsProvider, PlaintextDEK, DEK_SIZE_BYTES};

    /// Amazon Key Management Service
    pub struct AwsKms {
        kms_client: KmsClient,
        key_id: String,
    }

    impl AwsKms {
        /// Create a new instance from the ARN of a AWS KMS key.
        pub fn from_arn(arn: &str) -> Result<Self, KmsError> {
            let parts: Vec<&str> = arn.split(':').collect();

            if parts.len() != 6 {
                return Err(KmsError::InvalidConfiguration(format!(
                    "invalid KMS arn: too few parts {}",
                    parts.len()
                )));
            }

            let region_part = parts.get(3).expect("region is missing");
            let region = match Region::from_str(region_part) {
                Ok(r) => r,
                Err(e) => return Err(KmsError::InvalidConfiguration(e.description().to_string())),
            };

            Ok(AwsKms {
                kms_client: KmsClient::new(region),
                key_id: arn.to_string(),
            })
        }
    }

    impl KmsProvider for AwsKms {
        fn encrypt_dek(&self, plaintext_dek: &PlaintextDEK) -> Result<EncryptedDEK, KmsError> {
            if plaintext_dek.len() != DEK_SIZE_BYTES {
                return Err(KmsError::InvalidKey(format!(
                    "provided DEK wrong length: {}",
                    plaintext_dek.len()
                )));
            }

            let mut encrypt_req: EncryptRequest = Default::default();
            encrypt_req.key_id = self.key_id.clone();
            encrypt_req.plaintext = plaintext_dek.clone();

            match self.kms_client.encrypt(encrypt_req).sync() {
                Ok(result) => {
                    if let Some(ciphertext) = result.ciphertext_blob {
                        Ok(ciphertext)
                    } else {
                        Err(KmsError::OperationFailed(
                            "no ciphertext despite successful response".to_string(),
                        ))
                    }
                }
                Err(e) => Err(KmsError::OperationFailed(e.description().to_string())),
            }
        }

        fn decrypt_dek(&self, encrypted_dek: &EncryptedDEK) -> Result<PlaintextDEK, KmsError> {
            let mut decrypt_req: DecryptRequest = Default::default();
            decrypt_req.ciphertext_blob = encrypted_dek.clone();

            match self.kms_client.decrypt(decrypt_req).sync() {
                Ok(result) => {
                    if let Some(plaintext_dek) = result.plaintext {
                        if plaintext_dek.len() == DEK_SIZE_BYTES {
                            Ok(plaintext_dek)
                        } else {
                            Err(KmsError::InvalidKey(format!(
                                "decrypted DEK wrong length: {}",
                                plaintext_dek.len()
                            )))
                        }
                    } else {
                        Err(KmsError::OperationFailed(
                            "decrypted payload is empty".to_string(),
                        ))
                    }
                }
                Err(e) => Err(KmsError::OperationFailed(e.description().to_string())),
            }
        }
    }

    #[cfg(feature = "awskms")]
    impl fmt::Display for AwsKms {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "{}", self.key_id)
        }
    }
}

