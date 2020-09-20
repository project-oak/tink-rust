// Copyright 2020 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! AEAD functionality via GCP KMS.

use google_cloudkms1::{DecryptRequest, EncryptRequest};
use tink::utils::wrap_err;

/// `GcpAead` represents a GCP KMS service to a particular URI.
#[derive(Clone)]
pub struct GcpAead {
    key_uri: String,
    kms: crate::CloudKmsClient,
}

impl GcpAead {
    /// Return a new GCP KMS service.
    pub fn new(key_uri: &str, kms: crate::CloudKmsClient) -> GcpAead {
        GcpAead {
            key_uri: key_uri.to_string(),
            kms,
        }
    }
}

impl tink::Aead for GcpAead {
    fn encrypt(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, tink::TinkError> {
        let req = EncryptRequest {
            plaintext: Some(base64::encode_config(plaintext, base64::URL_SAFE)),
            additional_authenticated_data: Some(base64::encode_config(
                additional_data,
                base64::URL_SAFE,
            )),
            ..EncryptRequest::default()
        };
        let (http_rsp, rsp) = match &self.kms {
            crate::CloudKmsClient::WithDefaultCreds(kms) => kms
                .lock()
                .unwrap() // safe: lock
                .projects()
                .locations_key_rings_crypto_keys_encrypt(req, &self.key_uri)
                .doit()
                .map_err(|e| wrap_err("encrypt request failed", e))?,
            crate::CloudKmsClient::WithServiceAccount(kms) => kms
                .lock()
                .unwrap() // safe: lock
                .projects()
                .locations_key_rings_crypto_keys_encrypt(req, &self.key_uri)
                .doit()
                .map_err(|e| wrap_err("encrypt request failed", e))?,
        };
        if http_rsp.status != hyper::status::StatusCode::Ok {
            return Err(format!("failed request: {:?}", http_rsp).into());
        }
        let ct = rsp
            .ciphertext
            .ok_or_else(|| tink::TinkError::new("no ciphertext"))?;
        base64::decode(ct).map_err(|e| wrap_err("base64 decode failed", e))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, tink::TinkError> {
        let req = DecryptRequest {
            ciphertext: Some(base64::encode_config(ciphertext, base64::URL_SAFE)),
            additional_authenticated_data: Some(base64::encode_config(
                additional_data,
                base64::URL_SAFE,
            )),
            ..DecryptRequest::default()
        };
        let (http_rsp, rsp) = match &self.kms {
            crate::CloudKmsClient::WithDefaultCreds(kms) => kms
                .lock()
                .unwrap() // safe: lock
                .projects()
                .locations_key_rings_crypto_keys_decrypt(req, &self.key_uri)
                .doit()
                .map_err(|e| wrap_err("decrypt request failed", e))?,
            crate::CloudKmsClient::WithServiceAccount(kms) => kms
                .lock()
                .unwrap() // safe: lock
                .projects()
                .locations_key_rings_crypto_keys_decrypt(req, &self.key_uri)
                .doit()
                .map_err(|e| wrap_err("decrypt request failed", e))?,
        };
        if http_rsp.status != hyper::status::StatusCode::Ok {
            return Err(format!("failed request: {:?}", http_rsp).into());
        }

        let pt = rsp
            .plaintext
            .ok_or_else(|| tink::TinkError::new("no plaintext"))?;
        base64::decode(pt).map_err(|e| wrap_err("base64 decode failed", e))
    }
}
