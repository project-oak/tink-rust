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

//! Key manager for AES-SIV keys for deterministic AEAD.

use crate::subtle;
use prost::Message;
use tink::{
    registry::KeyManager,
    subtle::random::get_random_bytes,
    utils::{wrap_err, TinkError},
};

/// Maximal version of AES-SIV keys.
pub const AES_SIV_KEY_VERSION: u32 = 0;
/// Type URL of AES-SIV keys that Tink supports.
pub const AES_SIV_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesSivKey";

/// `AesSivKeyManager` generates new [`AesSivKey`](tink::proto::AesSivKey) keys and produces new
/// instances of [`subtle::AesSiv`].
#[derive(Default)]
pub(crate) struct AesSivKeyManager;

impl KeyManager for AesSivKeyManager {
    /// Create a [`subtle::AesSiv`] instance for the given serialized `AesSivKey` proto.
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesSivKeyManager: invalid key".into());
        }

        let key = tink::proto::AesSivKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesSivKeyManager: decode failed", e))?;
        validate_key(&key)?;
        match subtle::AesSiv::new(&key.key_value) {
            Ok(p) => Ok(tink::Primitive::DeterministicAead(std::sync::Arc::new(p))),
            Err(e) => Err(wrap_err("AesSivKeyManager: cannot create new primitive", e)),
        }
    }

    /// Create a new serialized key. `serialized_key_format` is not required, because there is only
    /// one valid key format.
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if !serialized_key_format.is_empty() {
            // If a key format was provided, check it is valid.
            let key_format = tink::proto::AesSivKeyFormat::decode(serialized_key_format)
                .map_err(|_| TinkError::new("AesSivKeyManager: invalid key format"))?;
            if key_format.key_size as usize != subtle::AES_SIV_KEY_SIZE {
                return Err(format!(
                    "AesSivKeyManager: key_format.key_size != {}",
                    subtle::AES_SIV_KEY_SIZE
                )
                .into());
            }
        }
        let key = tink::proto::AesSivKey {
            version: AES_SIV_KEY_VERSION,
            key_value: get_random_bytes(subtle::AES_SIV_KEY_SIZE),
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("Failed to encode new key", e))?;
        Ok(sk)
    }

    fn does_support(&self, type_url: &str) -> bool {
        type_url == AES_SIV_TYPE_URL
    }

    fn type_url(&self) -> String {
        AES_SIV_TYPE_URL.to_string()
    }

    fn key_material_type(&self) -> tink::proto::key_data::KeyMaterialType {
        tink::proto::key_data::KeyMaterialType::Symmetric
    }

    /// Create a new [`KeyData`](tink::proto::KeyData). `serialized_key_format` is not required,
    /// because there is only one valid key format.  It should be used solely by the key
    /// management API.
    fn new_key_data(
        &self,
        serialized_key_format: &[u8],
    ) -> Result<tink::proto::KeyData, TinkError> {
        let serialized_key = self.new_key(serialized_key_format)?;
        Ok(tink::proto::KeyData {
            type_url: self.type_url(),
            value: serialized_key,
            key_material_type: tink::proto::key_data::KeyMaterialType::Symmetric as i32,
        })
    }
}

/// Validate the given [`AesSivKey`](tink::proto::AesSivKey).
fn validate_key(key: &tink::proto::AesSivKey) -> Result<(), TinkError> {
    tink::keyset::validate_key_version(key.version, AES_SIV_KEY_VERSION)
        .map_err(|e| wrap_err("AesSivKeyManager", e))?;
    let key_size = key.key_value.len();
    if key_size != subtle::AES_SIV_KEY_SIZE {
        Err(format!("AesSivKeyManager: key_size != {}", subtle::AES_SIV_KEY_SIZE).into())
    } else {
        Ok(())
    }
}
