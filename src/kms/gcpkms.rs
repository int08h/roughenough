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

#[cfg(feature = "gcpkms")]
pub mod inner {
    extern crate futures;
    extern crate google_cloudkms1 as cloudkms1;
    extern crate hyper;
    extern crate hyper_rustls;
    extern crate tokio;
    extern crate yup_oauth2 as oauth2;

    use std::default::Default;
    use std::env;
    use std::path::Path;
    use std::result::Result;

    use data_encoding::BASE64;
    use tokio::runtime::Runtime;

    use crate::kms::{AD, EncryptedDEK, KmsError, KmsProvider, PlaintextDEK};

    use self::cloudkms1::api::{DecryptRequest, EncryptRequest};
    use self::cloudkms1::CloudKMS;
    use self::hyper::{Body, StatusCode};
    use self::oauth2::ServiceAccountKey;

    const GOOGLE_APP_CREDS: &str = &"GOOGLE_APPLICATION_CREDENTIALS";

    /// Google Cloud Key Management Service
    /// https://cloud.google.com/kms/
    pub struct GcpKms {
        key_resource_id: String,
        service_account: ServiceAccountKey,
        runtime: Runtime,
    }

    impl GcpKms {
        ///
        /// Create a new GcpKms from a Google Cloud KMS key resource ID of the form
        /// `projects/*/locations/*/keyRings/*/cryptoKeys/*`
        ///
        pub fn from_resource_id(resource_id: &str) -> Result<Self, KmsError> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            let svc_acct = load_gcp_credential(&rt)?;

            Ok(GcpKms {
                key_resource_id: resource_id.to_string(),
                service_account: svc_acct,
                runtime: rt,
            })
        }

        fn new_hub(&self) -> CloudKMS {
            let client =
                hyper::Client::builder().build(hyper_rustls::HttpsConnector::with_native_roots());

            let auth = self.runtime.block_on(async {
                oauth2::ServiceAccountAuthenticator::builder(self.service_account.clone())
                    .build()
                    .await
                    .expect("failed to create service account authenticator")
            });

            return CloudKMS::new(client, auth);
        }

        fn pretty_http_error(&self, resp: &hyper::Response<Body>) -> KmsError {
            let code = resp.status();
            KmsError::OperationFailed(format!("Response {} for {:?}", code, resp))
        }
    }

    impl KmsProvider for GcpKms {
        fn encrypt_dek(&self, plaintext_dek: &PlaintextDEK) -> Result<EncryptedDEK, KmsError> {
            let mut request = EncryptRequest::default();
            request.plaintext = Some(BASE64.encode(plaintext_dek));
            request.additional_authenticated_data = Some(BASE64.encode(AD.as_bytes()));

            let hub = self.new_hub();
            let result = self.runtime.block_on(async {
                hub.projects()
                    .locations_key_rings_crypto_keys_encrypt(request, &self.key_resource_id)
                    .doit()
                    .await
            });

            match result {
                Ok((http_resp, enc_resp)) => {
                    if http_resp.status() == StatusCode::OK {
                        let ciphertext = enc_resp.ciphertext.unwrap();
                        let ct = BASE64.decode(ciphertext.as_bytes())?;
                        Ok(ct)
                    } else {
                        Err(self.pretty_http_error(&http_resp))
                    }
                }
                Err(e) => Err(KmsError::OperationFailed(format!("encrypt_dek() {:?}", e))),
            }
        }

        fn decrypt_dek(&self, encrypted_dek: &EncryptedDEK) -> Result<PlaintextDEK, KmsError> {
            let mut request = DecryptRequest::default();
            request.ciphertext = Some(BASE64.encode(encrypted_dek));
            request.additional_authenticated_data = Some(BASE64.encode(AD.as_bytes()));

            let hub = self.new_hub();
            let result = self.runtime.block_on(async {
                hub.projects()
                    .locations_key_rings_crypto_keys_decrypt(request, &self.key_resource_id)
                    .doit()
                    .await
            });

            match result {
                Ok((http_resp, enc_resp)) => {
                    if http_resp.status() == StatusCode::OK {
                        let plaintext = enc_resp.plaintext.unwrap();
                        let ct = BASE64.decode(plaintext.as_bytes())?;
                        Ok(ct)
                    } else {
                        Err(self.pretty_http_error(&http_resp))
                    }
                }
                Err(e) => Err(KmsError::OperationFailed(format!("decrypt_dek() {:?}", e))),
            }
        }
    }

    /// Minimal implementation of Application Default Credentials.
    /// https://cloud.google.com/docs/authentication/production
    ///
    ///   1. Look for GOOGLE_APPLICATION_CREDENTIALS and load service account
    ///      credentials if found.
    ///   2. If not, error
    ///
    /// TODO attempt to load GCE default credentials from metadata server.
    /// This will be a bearer token instead of service account credential.

    fn load_gcp_credential(runtime: &Runtime) -> Result<ServiceAccountKey, KmsError> {
        if let Ok(gac) = env::var(GOOGLE_APP_CREDS.to_string()) {
            return if Path::new(&gac).exists() {
                match runtime.block_on(oauth2::read_service_account_key(&gac)) {
                    Ok(svc_acct_key) => Ok(svc_acct_key),
                    Err(e) => Err(KmsError::InvalidConfiguration(format!(
                        "Can't load service account credential '{}': {:?}",
                        gac, e
                    ))),
                }
            } else {
                Err(KmsError::InvalidConfiguration(format!(
                    "{} ='{}' does not exist",
                    GOOGLE_APP_CREDS, gac
                )))
            };
        }

        // TODO: call to GCE metadata service to get default credential from
        // http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

        panic!(
            "Failed to load service account credential. Is {} set?",
            GOOGLE_APP_CREDS
        );
    }
}
