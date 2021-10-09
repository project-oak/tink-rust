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

//! Key manager for AES-GCM-SIV keys.

use crate::subtle;
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::prost::Message;

/// Maximal version of AES-GCM-SIV keys.
pub const AES_GCM_SIV_KEY_VERSION: u32 = 0;
/// Type URL of AES-GCM-SIV keys that Tink supports.
pub const AES_GCM_SIV_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesGcmSivKey";

/// `AesGcmSivKeyManager` is an implementation of the `tink_core::registry::KeyManager` trait.
/// It generates new [`AesGcmSivKey`](tink_proto::AesGcmSivKey) keys and produces new instances of
/// [`subtle::AesGcmSiv`].
#[derive(Default)]
pub(crate) struct AesGcmSivKeyManager {}

impl tink_core::registry::KeyManager for AesGcmSivKeyManager {
    /// Create a [`subtle::AesGcmSiv`] for the given serialized [`tink_proto::AesGcmSivKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesGcmSivKeyManager: invalid key".into());
        }
        let key = tink_proto::AesGcmSivKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesGcmSivKeyManager: invalid key", e))?;
        validate_key(&key)?;
        match subtle::AesGcmSiv::new(&key.key_value) {
            Ok(p) => Ok(tink_core::Primitive::Aead(Box::new(p))),
            Err(e) => Err(wrap_err(
                "AesGcmSivKeyManager: cannot create new primitive",
                e,
            )),
        }
    }

    /// Create a new key according to specification the given serialized
    /// [`tink_proto::AesGcmSivKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesGcmSivKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::AesGcmSivKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("AesGcmSivKeyManager: invalid key format", e))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("AesGcmSivKeyManager: invalid key format", e))?;
        let key_value = tink_core::subtle::random::get_random_bytes(key_format.key_size as usize);
        let key = tink_proto::AesGcmSivKey {
            version: AES_GCM_SIV_KEY_VERSION,
            key_value,
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("AesGcmSivKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        AES_GCM_SIV_TYPE_URL
    }
    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`tink_proto::AesGcmSivKey`].
fn validate_key(key: &tink_proto::AesGcmSivKey) -> Result<(), TinkError> {
    tink_core::keyset::validate_key_version(key.version, AES_GCM_SIV_KEY_VERSION)
        .map_err(|e| wrap_err("AesGcmSivKeyManager", e))?;
    let key_size = key.key_value.len();
    crate::subtle::validate_aes_key_size(key_size).map_err(|e| wrap_err("AesGcmSivKeyManager", e))
}

/// Validate the given [`tink_proto::AesGcmSivKeyFormat`].
fn validate_key_format(format: &tink_proto::AesGcmSivKeyFormat) -> Result<(), TinkError> {
    crate::subtle::validate_aes_key_size(format.key_size as usize)
        .map_err(|e| wrap_err("AesGcmSivKeyManager", e))
}
