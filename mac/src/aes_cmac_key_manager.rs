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

//! Key manager for AES-CMAC keys for MAC.

use alloc::{boxed::Box, vec::Vec};
use prost::Message;
use tink_core::{utils::wrap_err, TinkError};

/// Maximal version of AES-CMAC keys.
pub const CMAC_KEY_VERSION: u32 = 0;
/// Type URL of AES-CMAC keys that Tink supports.
pub const CMAC_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesCmacKey";

/// Generates new AES-CMAC keys and produces new instances of AES-CMAC.
#[derive(Default)]
pub(crate) struct AesCmacKeyManager;

impl tink_core::registry::KeyManager for AesCmacKeyManager {
    /// Create an [`AesCmac`](crate::subtle::AesCmac) instance for the given serialized
    /// [`AesCmacKey`](tink_proto::AesCmacKey) proto.
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesCmacKeyManager: invalid key".into());
        }

        let key = tink_proto::AesCmacKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesCmacKeyManager: decode failed", e))?;
        let tag_size = validate_key(&key)?;
        match crate::subtle::AesCmac::new(&key.key_value, tag_size) {
            Ok(p) => Ok(tink_core::Primitive::Mac(Box::new(p))),
            Err(e) => Err(wrap_err(
                "AesCmacKeyManager: cannot create new primitive",
                e,
            )),
        }
    }

    /// Generate a new serialized [`AesCmacKey`](tink_proto::AesCmacKey) according to
    /// specification in the given [`AesCmacKeyFormat`](tink_proto::AesCmacKeyFormat).
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesCmacKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::AesCmacKeyFormat::decode(serialized_key_format)
            .map_err(|_| TinkError::new("AesCmacKeyManager: invalid key format"))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("AesCmacKeyManager: invalid key format", e))?;
        let key_value = tink_core::subtle::random::get_random_bytes(key_format.key_size as usize);
        let mut sk = Vec::new();
        tink_proto::AesCmacKey {
            version: CMAC_KEY_VERSION,
            params: key_format.params,
            key_value,
        }
        .encode(&mut sk)
        .map_err(|e| wrap_err("AesCmacKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        CMAC_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`AesCmacKey`](tink_proto::AesCmacKey). It only validates the version of the
/// key because other parameters will be validated in primitive construction.
fn validate_key(key: &tink_proto::AesCmacKey) -> Result<usize, TinkError> {
    tink_core::keyset::validate_key_version(key.version, CMAC_KEY_VERSION)
        .map_err(|e| wrap_err("AesCmacKeyManager: invalid version", e))?;
    let key_size = key.key_value.len();
    match &key.params {
        None => Err("AesCmacKeyManager: missing AES-CMAC params".into()),
        Some(params) => {
            crate::subtle::validate_cmac_params(key_size, params.tag_size as usize)?;
            Ok(params.tag_size as usize)
        }
    }
}

/// Validate the given [`AesCmacKeyFormat`](tink_proto::AesCmacKeyFormat).
fn validate_key_format(format: &tink_proto::AesCmacKeyFormat) -> Result<(), TinkError> {
    match &format.params {
        None => Err("missing AES-CMAC params".into()),
        Some(params) => {
            crate::subtle::validate_cmac_params(format.key_size as usize, params.tag_size as usize)
        }
    }
}
