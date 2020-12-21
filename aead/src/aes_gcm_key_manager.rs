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

//! Key manager for AES-GCM keys.

use crate::subtle;
use prost::Message;
use tink::{utils::wrap_err, TinkError};

/// Maximal version of AES-GCM keys.
pub const AES_GCM_KEY_VERSION: u32 = 0;
/// Type URL of AES-GCM keys that Tink supports.
pub const AES_GCM_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesGcmKey";

/// `AesGcmKeyManager` is an implementation of the `tink::registry::KeyManager` trait.
/// It generates new [`AesGcmKey`](tink_proto::AesGcmKey) keys and produces new instances of
/// [`subtle::AesGcm`].
#[derive(Default)]
pub(crate) struct AesGcmKeyManager {}

impl tink::registry::KeyManager for AesGcmKeyManager {
    /// Create a [`subtle::AesGcm`] for the given serialized [`tink_proto::AesGcmKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesGcmKeyManager: invalid key".into());
        }
        let key = tink_proto::AesGcmKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesGcmKeyManager: invalid key", e))?;
        validate_key(&key)?;
        match subtle::AesGcm::new(&key.key_value) {
            Ok(p) => Ok(tink::Primitive::Aead(Box::new(p))),
            Err(e) => Err(wrap_err("AesGcmKeyManager: cannot create new primitive", e)),
        }
    }

    /// Create a new key according to specification the given serialized
    /// [`tink_proto::AesGcmKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesGcmKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::AesGcmKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("AesGcmKeyManager: invalid key format", e))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("AesGcmKeyManager: invalid key format", e))?;
        let key_value = tink::subtle::random::get_random_bytes(key_format.key_size as usize);
        let key = tink_proto::AesGcmKey {
            version: AES_GCM_KEY_VERSION,
            key_value,
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("AesGcmKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        AES_GCM_TYPE_URL
    }
    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`tink_proto::AesGcmKey`].
fn validate_key(key: &tink_proto::AesGcmKey) -> Result<(), TinkError> {
    tink::keyset::validate_key_version(key.version, AES_GCM_KEY_VERSION)
        .map_err(|e| wrap_err("AesGcmKeyManager", e))?;
    let key_size = key.key_value.len();
    crate::subtle::validate_aes_key_size(key_size).map_err(|e| wrap_err("AesGcmKeyManager", e))
}

/// Validate the given [`tink_proto::AesGcmKeyFormat`].
fn validate_key_format(format: &tink_proto::AesGcmKeyFormat) -> Result<(), TinkError> {
    crate::subtle::validate_aes_key_size(format.key_size as usize)
        .map_err(|e| wrap_err("AesGcmKeyManager", e))
}
