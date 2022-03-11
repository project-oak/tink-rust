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

//! Key manager for AES-CMAC keys for HMAC.

use tink_core::{utils::wrap_err, TinkError};
use tink_proto::{prost::Message, HashType};

/// Maximal version of HMAC keys.
pub const HMAC_KEY_VERSION: u32 = 0;
/// Type URL of HMAC keys that Tink supports.
pub const HMAC_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.HmacKey";

/// Generates new HMAC keys and produces new instances of HMAC.
#[derive(Default)]
pub(crate) struct HmacKeyManager;

impl tink_core::registry::KeyManager for HmacKeyManager {
    /// Create an HMAC instance for the given serialized [`HmacKey`](tink_proto::HmacKey) proto.
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("HmacKeyManager: invalid key".into());
        }

        let key = tink_proto::HmacKey::decode(serialized_key)
            .map_err(|e| wrap_err("HmacKeyManager: decode failed", e))?;
        validate_key(&key)?;

        let params = match &key.params {
            None => return Err("HmacKeyManager: no key params".into()),
            Some(p) => p,
        };
        let hash = HashType::from_i32(params.hash).unwrap_or(HashType::UnknownHash);
        match crate::subtle::Hmac::new(hash, &key.key_value, params.tag_size as usize) {
            Ok(p) => Ok(tink_core::Primitive::Mac(Box::new(p))),
            Err(e) => Err(wrap_err("HmacKeyManager: cannot create new primitive", e)),
        }
    }

    /// Generate a new serialized [`HmacKey`](tink_proto::HmacKey) according to specification in
    /// the given [`HmacKeyFormat`](tink_proto::HmacKeyFormat).
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("HmacKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::HmacKeyFormat::decode(serialized_key_format)
            .map_err(|_| "HmacKeyManager: invalid key format")?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("HmacKeyManager: invalid key format", e))?;
        let key_value = tink_core::subtle::random::get_random_bytes(key_format.key_size as usize);
        let mut sk = Vec::new();
        tink_proto::HmacKey {
            version: HMAC_KEY_VERSION,
            params: key_format.params,
            key_value,
        }
        .encode(&mut sk)
        .map_err(|e| wrap_err("HmacKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        HMAC_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`HmacKey`](tink_proto::HmacKey). It only validates the version of the
/// key because other parameters will be validated in primitive construction.
fn validate_key(key: &tink_proto::HmacKey) -> Result<(), TinkError> {
    tink_core::keyset::validate_key_version(key.version, HMAC_KEY_VERSION)
        .map_err(|e| wrap_err("HmacKeyManager: invalid version", e))?;
    let key_size = key.key_value.len();
    match &key.params {
        None => Err("HmacKeyManager: missing HMAC params".into()),
        Some(params) => {
            let hash = HashType::from_i32(params.hash).unwrap_or(HashType::UnknownHash);
            crate::subtle::validate_hmac_params(hash, key_size, params.tag_size as usize)
        }
    }
}

/// Validate the given [`HmacKeyFormat`](tink_proto::HmacKeyFormat).
fn validate_key_format(format: &tink_proto::HmacKeyFormat) -> Result<(), TinkError> {
    match &format.params {
        None => Err("missing HMAC params".into()),
        Some(params) => {
            let hash = HashType::from_i32(params.hash).unwrap_or(HashType::UnknownHash);
            crate::subtle::validate_hmac_params(
                hash,
                format.key_size as usize,
                params.tag_size as usize,
            )
        }
    }
}
