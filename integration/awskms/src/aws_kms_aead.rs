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

//! AEAD functionality via AWS Cloud KMS.

use rusoto_kms::Kms;
use std::{cell::RefCell, collections::HashMap, rc::Rc};
use tink_core::utils::wrap_err;

/// `AwsAead` represents a AWS KMS service to a particular URI.
#[derive(Clone)]
pub struct AwsAead {
    key_uri: String,
    kms: rusoto_kms::KmsClient,
    // The Tokio runtime to execute KMS requests on, wrapped in:
    //  - a `RefCell` for interior mutability (the [`tink_core::Aead`] trait's methods take
    //    `&self`)
    //  - an `Rc` to allow `Clone`, as required by the trait bound on [`tink_core::Aead`].
    runtime: Rc<RefCell<tokio::runtime::Runtime>>,
}

impl AwsAead {
    /// Return a new AWS KMS service.
    /// `key_uri` must have the following format: `arn:<partition>:kms:<region>:[:path]`.
    /// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
    pub(crate) fn new(
        key_uri: &str,
        kms: rusoto_kms::KmsClient,
    ) -> Result<AwsAead, tink_core::TinkError> {
        Ok(AwsAead {
            key_uri: key_uri.to_string(),
            kms,
            runtime: Rc::new(RefCell::new(
                tokio::runtime::Builder::new()
                    .basic_scheduler()
                    .enable_all()
                    .build()
                    .map_err(|e| wrap_err("failed to build tokio runtime", e))?,
            )),
        })
    }
}

impl tink_core::Aead for AwsAead {
    fn encrypt(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, tink_core::TinkError> {
        let ad = hex::encode(additional_data);
        let encryption_context = if ad.is_empty() {
            None
        } else {
            let mut context = HashMap::new();
            context.insert("additionalData".to_string(), ad);
            Some(context)
        };
        let req = rusoto_kms::EncryptRequest {
            encryption_algorithm: None, // use default
            grant_tokens: None,
            key_id: self.key_uri.clone(),
            encryption_context,
            plaintext: plaintext.to_vec().into(),
        };
        let rsp = self
            .runtime
            .borrow_mut()
            .block_on(self.kms.encrypt(req))
            .map_err(|e| wrap_err("request failed", e))?;

        match rsp.ciphertext_blob {
            None => Err("no ciphertext".into()),
            Some(ct) => Ok(ct.to_vec()),
        }
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, tink_core::TinkError> {
        let ad = hex::encode(additional_data);
        let encryption_context = if ad.is_empty() {
            None
        } else {
            let mut context = HashMap::new();
            context.insert("additionalData".to_string(), ad);
            Some(context)
        };
        let req = rusoto_kms::DecryptRequest {
            ciphertext_blob: ciphertext.to_vec().into(),
            encryption_algorithm: None, // use default
            encryption_context,
            grant_tokens: None,
            key_id: Some(self.key_uri.clone()),
        };
        let rsp = self
            .runtime
            .borrow_mut()
            .block_on(self.kms.decrypt(req))
            .map_err(|e| wrap_err("request failed", e))?;
        if let Some(key_id) = rsp.key_id {
            if key_id != self.key_uri {
                return Err("decryption failed: wrong key id".into());
            }
        } else {
            return Err("decryption failed: no key id".into());
        }
        match rsp.plaintext {
            None => Err("no plaintext in response".into()),
            Some(b) => Ok(b.to_vec()),
        }
    }
}
