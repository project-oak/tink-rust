// Copyright 2026 The Tink-Rust Authors
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

//! Key manager for AES-EAX keys.

use crate::subtle;
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::prost::Message;

/// Maximal version of AES-EAX keys.
pub const AES_EAX_KEY_VERSION: u32 = 0;
/// Type URL of AES-EAX keys that Tink supports.
pub const AES_EAX_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesEaxKey";

/// `AesEaxKeyManager` is an implementation of the `tink_core::registry::KeyManager` trait.
/// It generates new [`AesEaxKey`](tink_proto::AesEaxKey) keys and produces new instances of
/// [`subtle::AesEax`].
#[derive(Default)]
pub(crate) struct AesEaxKeyManager {}

impl tink_core::registry::KeyManager for AesEaxKeyManager {
    /// Create a [`subtle::AesEax`] for the given serialized [`tink_proto::AesEaxKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesEaxKeyManager: invalid key".into());
        }

        let key = tink_proto::AesEaxKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesEaxKeyManager: invalid key", e))?;
        validate_key(&key)?;

        let params = key
            .params
            .ok_or_else(|| TinkError::new("AesEaxKeyManager: missing params"))?;

        match subtle::AesEax::new(&key.key_value, params.iv_size as usize) {
            Ok(p) => Ok(tink_core::Primitive::Aead(Box::new(p))),
            Err(e) => Err(wrap_err("AesEaxKeyManager: cannot create new primitive", e)),
        }
    }

    /// Create a new key according to specification the given serialized
    /// [`tink_proto::AesEaxKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesEaxKeyManager: invalid key format".into());
        }

        let key_format = tink_proto::AesEaxKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("AesEaxKeyManager: invalid key format", e))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("AesEaxKeyManager: invalid key format", e))?;

        let key_value = tink_core::subtle::random::get_random_bytes(key_format.key_size as usize);
        let key = tink_proto::AesEaxKey {
            version: AES_EAX_KEY_VERSION,
            params: key_format.params,
            key_value,
        };

        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("AesEaxKeyManager: failed to encode new key", e))?;

        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        AES_EAX_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`tink_proto::AesEaxKey`].
fn validate_key(key: &tink_proto::AesEaxKey) -> Result<(), TinkError> {
    tink_core::keyset::validate_key_version(key.version, AES_EAX_KEY_VERSION)
        .map_err(|e| wrap_err("AesEaxKeyManager", e))?;

    crate::subtle::validate_aes_key_size(key.key_value.len())
        .map_err(|e| wrap_err("AesEaxKeyManager", e))?;

    let params = key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesEaxKeyManager: missing params"))?;
    validate_aes_eax_params(params).map_err(|e| wrap_err("AesEaxKeyManager", e))
}

/// Validate the given [`tink_proto::AesEaxKeyFormat`].
fn validate_key_format(format: &tink_proto::AesEaxKeyFormat) -> Result<(), TinkError> {
    crate::subtle::validate_aes_key_size(format.key_size as usize)
        .map_err(|e| wrap_err("AesEaxKeyManager", e))?;

    let params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesEaxKeyManager: missing params"))?;
    validate_aes_eax_params(params).map_err(|e| wrap_err("AesEaxKeyManager", e))
}

/// Validate AES-EAX parameters.
fn validate_aes_eax_params(params: &tink_proto::AesEaxParams) -> Result<(), TinkError> {
    crate::subtle::validate_iv_size(params.iv_size as usize)
}
