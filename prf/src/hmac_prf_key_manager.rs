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

//! Key manager for HMAC keys for PRF.

use crate::subtle;
use std::convert::TryFrom;
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::{prost::Message, HashType};

/// Maximal version of HMAC PRF keys.
pub const HMAC_PRF_KEY_VERSION: u32 = 0;
/// Type URL of HMAC PRF keys that Tink supports.
pub const HMAC_PRF_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.HmacPrfKey";

/// Generates new HMAC keys and produces new instances of HMAC.
#[derive(Default)]
pub(crate) struct HmacPrfKeyManager;

impl tink_core::registry::KeyManager for HmacPrfKeyManager {
    /// Construct an HMAC instance for the given serialized [`HmacPrfKey`](tink_proto::HmacPrfKey).
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("HmacPrfKeyManager: invalid key".into());
        }
        let key = tink_proto::HmacPrfKey::decode(serialized_key)
            .map_err(|_| "HmacPrfKeyManager: invalid key")?;
        let (_params, hash) = validate_key(&key).map_err(|e| wrap_err("HmacPrfKeyManager", e))?;

        match subtle::HmacPrf::new(hash, &key.key_value) {
            Ok(p) => Ok(tink_core::Primitive::Prf(Box::new(p))),
            Err(e) => Err(wrap_err("HmacPrfManager: cannot create new primitive", e)),
        }
    }

    /// Generates a new [`HmacPrfKey`](tink_proto::HmacPrfKey) according to specification in the
    /// given [`HmacPrfKeyFormat`](tink_proto::HmacPrfKeyFormat).
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("HmacPrfKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::HmacPrfKeyFormat::decode(serialized_key_format)
            .map_err(|_| "HmacPrfKeyManager: invalid key format")?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("HmacPrfKeyManager: invalid key format", e))?;

        let key_value = tink_core::subtle::random::get_random_bytes(key_format.key_size as usize);
        let mut sk = Vec::new();
        tink_proto::HmacPrfKey {
            version: HMAC_PRF_KEY_VERSION,
            params: key_format.params,
            key_value,
        }
        .encode(&mut sk)
        .map_err(|e| wrap_err("HmacPrfKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        HMAC_PRF_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`HmacPrfKey`](tink_proto::HmacPrfKey). It only validates the version of the
/// key because other parameters will be validated in primitive construction.
fn validate_key(
    key: &tink_proto::HmacPrfKey,
) -> Result<(tink_proto::HmacPrfParams, HashType), TinkError> {
    tink_core::keyset::validate_key_version(key.version, HMAC_PRF_KEY_VERSION)
        .map_err(|e| wrap_err("invalid version", e))?;
    let key_size = key.key_value.len();
    let params = match key.params.as_ref() {
        None => return Err("no key params".into()),
        Some(p) => p,
    };
    let hash = HashType::try_from(params.hash).unwrap_or(HashType::UnknownHash);
    subtle::validate_hmac_prf_params(hash, key_size)?;
    Ok((*params, hash))
}

/// Validates the given [`HmacPrfKeyFormat`](tink_proto::HmacPrfKeyFormat).
fn validate_key_format(format: &tink_proto::HmacPrfKeyFormat) -> Result<(), TinkError> {
    let params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no params"))?;
    let hash = HashType::try_from(params.hash).unwrap_or(HashType::UnknownHash);
    subtle::validate_hmac_prf_params(hash, format.key_size as usize)
}
