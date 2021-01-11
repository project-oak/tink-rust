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

//! Key manager for AES-CMAC keys for PRF.

use crate::subtle;
use prost::Message;
use tink_core::{utils::wrap_err, TinkError};

/// Maximal version of AES-CMAC PRF keys.
pub const AES_CMAC_PRF_KEY_VERSION: u32 = 0;
/// Type URL of AES-CMAC PRF keys that Tink supports.
pub const AES_CMAC_PRF_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

/// Generates new AES-CMAC keys and produces new instances of AES-CMAC.
#[derive(Default)]
pub(crate) struct AesCmacPrfKeyManager;

impl tink_core::registry::KeyManager for AesCmacPrfKeyManager {
    /// Create an [`AesCmacPrf`](crate::subtle::AesCmacPrf) instance for the given serialized
    /// [`AesCmacPrfKey`](tink_proto::AesCmacPrfKey) proto.
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesCmacPrfKeyManager: invalid key".into());
        }

        let key = tink_proto::AesCmacPrfKey::decode(serialized_key)
            .map_err(|_| TinkError::new("AesCmacPrfKeyManager: invalid key"))?;
        validate_key(&key)?;
        match subtle::AesCmacPrf::new(&key.key_value) {
            Ok(p) => Ok(tink_core::Primitive::Prf(Box::new(p))),
            Err(e) => Err(wrap_err(
                "AesCmacPrfManager: cannot create new primitive",
                e,
            )),
        }
    }

    /// Generate a new serialized [`AesCmacPrfKey`](tink_proto::AesCmacPrfKey) according to
    /// specification in the given [`AesCmacPrfKeyFormat`](tink_proto::AesCmacPrfKeyFormat).
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesCmacPrfKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::AesCmacPrfKeyFormat::decode(serialized_key_format)
            .map_err(|_| TinkError::new("AesCmacPrfKeyManager: invalid key format"))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("AesCmacPrfKeyManager: invalid key format", e))?;
        let key_value = tink_core::subtle::random::get_random_bytes(key_format.key_size as usize);

        let mut sk = Vec::new();
        tink_proto::AesCmacPrfKey {
            version: AES_CMAC_PRF_KEY_VERSION,
            key_value,
        }
        .encode(&mut sk)
        .map_err(|e| wrap_err("AesCmacPrfKeyManager: Failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        AES_CMAC_PRF_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`AesCmacPrfKey`](tink_proto::AesCmacPrfKey). It only validates the version
/// of the key because other parameters will be validated in primitive construction.
fn validate_key(key: &tink_proto::AesCmacPrfKey) -> Result<(), TinkError> {
    tink_core::keyset::validate_key_version(key.version, AES_CMAC_PRF_KEY_VERSION)
        .map_err(|e| wrap_err("AesCmacPrfKeyManager: invalid version", e))?;
    let key_size = key.key_value.len();
    subtle::validate_aes_cmac_prf_params(key_size)
}

/// Validate the given [`AesCmacPrfKeyFormat`](tink_proto::AesCmacPrfKeyFormat).
fn validate_key_format(format: &tink_proto::AesCmacPrfKeyFormat) -> Result<(), TinkError> {
    subtle::validate_aes_cmac_prf_params(format.key_size as usize)
}
