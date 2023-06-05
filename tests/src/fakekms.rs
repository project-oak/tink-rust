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

//! Provide a fake implementation of tink::registry::KmsClient.
//!
//! Normally, a 'keyURI' identifies a key that is stored remotely by the KMS,
//! and every operation is executed remotely using a RPC call to the KMS, since
//! the key should not be sent to the client.
//! In this fake implementation we want to avoid these RPC calls. We achieve this
//! by encoding the key in the 'keyURI'. So the client simply needs to decode
//! the key and generate an AEAD out of it. This is of course insecure and should
//! only be used in testing.

use base64::Engine;
use tink_core::{utils::wrap_err, TinkError};

const FAKE_PREFIX: &str = "fake-kms://";

#[derive(Debug)]
pub struct FakeClient {
    uri_prefix: String,
}

impl FakeClient {
    /// Returns a fake KMS client which will handle keys with `uri_prefix` prefix.
    /// `key_uri` must have the following format: `fake-kms://<base64 encoded aead keyset>`.
    pub fn new(uri_prefix: &str) -> Result<Self, TinkError> {
        if !uri_prefix.to_lowercase().starts_with(FAKE_PREFIX) {
            return Err(
                format!("UriPrefix must start with {FAKE_PREFIX}, but got {uri_prefix}").into(),
            );
        }
        Ok(FakeClient {
            uri_prefix: uri_prefix.to_string(),
        })
    }
}

impl tink_core::registry::KmsClient for FakeClient {
    fn supported(&self, key_uri: &str) -> bool {
        key_uri.starts_with(&self.uri_prefix)
    }

    fn get_aead(&self, key_uri: &str) -> Result<Box<dyn tink_core::Aead>, crate::TinkError> {
        if !self.supported(key_uri) {
            return Err(format!(
                "key_uri must start with prefix {}, but got {}",
                self.uri_prefix, key_uri
            )
            .into());
        }

        let encoded_keyset = if let Some(stripped) = key_uri.strip_prefix(FAKE_PREFIX) {
            stripped
        } else {
            key_uri
        };

        let keyset_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_keyset)
            .map_err(|e| wrap_err("Failed to decode", e))?;
        let cursor = std::io::Cursor::new(keyset_data);
        let mut reader = tink_core::keyset::BinaryReader::new(cursor);
        let handle = tink_core::keyset::insecure::read(&mut reader)?;
        tink_aead::new(&handle)
    }
}

/// Return a new, random fake KMS key URI.
pub fn new_key_uri() -> Result<String, TinkError> {
    let handle = tink_core::keyset::Handle::new(&tink_aead::aes128_gcm_key_template())?;
    let mut buf = vec![];
    let mut writer = tink_core::keyset::BinaryWriter::new(&mut buf);
    tink_core::keyset::insecure::write(&handle, &mut writer)?;

    let mut output = FAKE_PREFIX.to_string();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(buf, &mut output);
    Ok(output)
}
