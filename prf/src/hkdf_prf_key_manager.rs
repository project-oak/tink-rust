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

//! Key manager for HKDF keys for PRF.

use crate::subtle;
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::{prost::Message, HashType};

/// Maximal version of HKDF PRF keys.
pub const HKDF_PRF_KEY_VERSION: u32 = 0;
/// Type URL of HKDF PRF keys that Tink supports.
pub const HKDF_PRF_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.HkdfPrfKey";

/// Generates new HKDF PRF keys and produces new instances of HKDF.
#[derive(Default)]
pub(crate) struct HkdfPrfKeyManager;

impl tink_core::registry::KeyManager for HkdfPrfKeyManager {
    /// Construct an HKDF instance for the given serialized [`HkdfPrfKey`](tink_proto::HkdfPrfKey).
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("HkdfPrfKeyManager: invalid key".into());
        }
        let key = tink_proto::HkdfPrfKey::decode(serialized_key)
            .map_err(|_| TinkError::new("HkdfPrfKeyManager: invalid key"))?;
        let (params, hash) = validate_key(&key).map_err(|e| wrap_err("HkdfPrfKeyManager", e))?;

        match subtle::HkdfPrf::new(hash, &key.key_value, &params.salt) {
            Ok(p) => Ok(tink_core::Primitive::Prf(Box::new(p))),
            Err(e) => Err(wrap_err("HkdfPrfManager: cannot create new primitive", e)),
        }
    }

    /// Generate a new [`HkdfPrfKey`](tink_proto::HkdfPrfKey) according to specification in the
    /// given [`HkdfPrfKeyFormat`](tink_proto::HkdfPrfKeyFormat).
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("HkdfPrfKeyManager: invalid key format".into());
        }

        let key_format = tink_proto::HkdfPrfKeyFormat::decode(serialized_key_format)
            .map_err(|_| TinkError::new("HkdfPrfKeyManager: invalid key format"))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("HkdfPrfKeyManager: invalid key format", e))?;

        let key_value = tink_core::subtle::random::get_random_bytes(key_format.key_size as usize);
        let mut sk = Vec::new();

        tink_proto::HkdfPrfKey {
            version: HKDF_PRF_KEY_VERSION,
            params: key_format.params,
            key_value,
        }
        .encode(&mut sk)
        .map_err(|e| wrap_err("HkdfPrfKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        HKDF_PRF_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`HkdfPrfKey`](tink_proto::HkdfPrfKey). It only validates the version of the
/// key because other parameters will be validated in primitive construction.
fn validate_key(
    key: &tink_proto::HkdfPrfKey,
) -> Result<(tink_proto::HkdfPrfParams, HashType), TinkError> {
    tink_core::keyset::validate_key_version(key.version, HKDF_PRF_KEY_VERSION)
        .map_err(|e| wrap_err("HkdfPrfKeyManager: invalid version", e))?;
    let key_size = key.key_value.len();
    let params = match key.params.as_ref() {
        None => return Err("HkdfPrfKeyManager: no key params".into()),
        Some(p) => p,
    };
    let hash = HashType::from_i32(params.hash).unwrap_or(HashType::UnknownHash);
    subtle::validate_hkdf_prf_params(hash, key_size, &params.salt)?;
    Ok((params.clone(), hash))
}

/// Validate the given [`HkdfPrfKeyFormat`](tink_proto::HkdfPrfKeyFormat).
fn validate_key_format(format: &tink_proto::HkdfPrfKeyFormat) -> Result<(), TinkError> {
    let params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no key params"))?;
    let hash = HashType::from_i32(params.hash).unwrap_or(HashType::UnknownHash);
    subtle::validate_hkdf_prf_params(hash, format.key_size as usize, &params.salt)
}
