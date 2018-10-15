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

#[cfg(feature = "gcpkms")]
pub mod inner {
    extern crate base64;
    extern crate hyper;
    extern crate hyper_rustls;
    extern crate yup_oauth2 as oauth2;
    extern crate google_cloudkms1 as cloudkms1;

    use std::result::Result;
    use std::default::Default;
    use std::error::Error;
    use std::fmt;
    use std::fmt::Formatter;
    use std::str::FromStr;

    use self::oauth2::{service_account_key_from_file, ServiceAccountAccess, ServiceAccountKey};
    use self::cloudkms1::CloudKMS;
    use self::cloudkms1::{Result as CloudKmsResult, Error as CloudKmsError, EncryptRequest, DecryptRequest};
    use self::hyper::net::HttpsConnector;
    use self::hyper::status::StatusCode;
    use self::hyper_rustls::TlsClient;

    use kms::{EncryptedDEK, KmsError, KmsProvider, PlaintextDEK};

    pub struct GcpKms {
        key_resource_id: String,
        service_account: ServiceAccountKey,
    }

    impl GcpKms {
        pub fn from_resource_id(resource_id: &str) -> Result<Self, KmsError> {
            let client_secret = oauth2::service_account_key_from_file(&"creds.json".to_string())
                .unwrap();

            Ok(GcpKms {
                key_resource_id: resource_id.to_string(),
                service_account: client_secret
            })
        }
    }

    impl KmsProvider for GcpKms {
        fn encrypt_dek(&self, plaintext_dek: &PlaintextDEK) -> Result<EncryptedDEK, KmsError> {
            let client1 = hyper::Client::with_connector(HttpsConnector::new(TlsClient::new()));
            let access = oauth2::ServiceAccountAccess::new(self.service_account.clone(), client1);

            let client2 = hyper::Client::with_connector(HttpsConnector::new(TlsClient::new()));
            let hub = CloudKMS::new(client2, access);

            let mut request = EncryptRequest::default();
            request.plaintext = Some(base64::encode(plaintext_dek));

            let result = hub
                .projects()
                .locations_key_rings_crypto_keys_encrypt(request, &self.key_resource_id)
                .doit();

            match result {
                Ok((http_resp, enc_resp)) => {
                    if http_resp.status == StatusCode::Ok {
                        let ciphertext = enc_resp.ciphertext.unwrap();
                        let ct = base64::decode(&ciphertext)?;
                        Ok(ct)
                    } else {
                        Err(KmsError::OperationFailed(format!("{:?}", http_resp)))
                    }
                }
                Err(e) => Err(KmsError::OperationFailed(e.description().to_string()))
            }
        }

        fn decrypt_dek(&self, encrypted_dek: &EncryptedDEK) -> Result<PlaintextDEK, KmsError> {
            let client1 = hyper::Client::with_connector(HttpsConnector::new(TlsClient::new()));
            let access = oauth2::ServiceAccountAccess::new(self.service_account.clone(), client1);

            let client2 = hyper::Client::with_connector(HttpsConnector::new(TlsClient::new()));
            let hub = CloudKMS::new(client2, access);

            let mut request = DecryptRequest::default();
            request.ciphertext = Some(base64::encode(encrypted_dek));

            let result = hub
                .projects()
                .locations_key_rings_crypto_keys_decrypt(request, &self.key_resource_id)
                .doit();

            match result {
                Ok((http_resp, enc_resp)) => {
                    if http_resp.status == StatusCode::Ok {
                        let plaintext = enc_resp.plaintext.unwrap();
                        let ct = base64::decode(&plaintext)?;
                        Ok(ct)
                    } else {
                        Err(KmsError::OperationFailed(format!("{:?}", http_resp)))
                    }
                }
                Err(e) => Err(KmsError::OperationFailed(e.description().to_string()))
            }
        }
    }
}


