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
use prost::Message;
use tink::{proto::HashType, utils::wrap_err, TinkError};

/// Maximal version of HKDF PRF keys.
pub const HKDF_PRF_KEY_VERSION: u32 = 0;
/// Type URL of HKDF PRF keys that Tink supports.
pub const HKDF_PRF_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.HkdfPrfKey";

/// Generates new HKDF PRF keys and produces new instances of HKDF.
#[derive(Default)]
pub(crate) struct HkdfPrfKeyManager;

impl tink::registry::KeyManager for HkdfPrfKeyManager {
    /// Construct an HKDF instance for the given serialized [`HkdfPrfKey`](tink::proto::HkdfPrfKey).
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("HkdfPrfKeyManager: invalid key".into());
        }
        let key = tink::proto::HkdfPrfKey::decode(serialized_key)
            .map_err(|_| TinkError::new("HkdfPrfKeyManager: invalid key"))?;
        validate_key(&key)?;
        let params = key
            .params
            .ok_or_else(|| TinkError::new("HkdfPrfKeyManager: no key parameters"))?;
        let hash = HashType::from_i32(params.hash).unwrap_or(HashType::UnknownHash);

        match subtle::HkdfPrf::new(hash, &key.key_value, &params.salt) {
            Ok(p) => Ok(tink::Primitive::Prf(std::sync::Arc::new(p))),
            Err(e) => Err(wrap_err("HkdfPrfManager: cannot create new primitive", e)),
        }
    }

    /// Generate a new [`HkdfPrfKey`](tink::proto::HkdfPrfKey) according to specification in the
    /// given [`HkdfPrfKeyFormat`](tink::proto::HkdfPrfKeyFormat).
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("HkdfPrfKeyManager: invalid key format".into());
        }

        let key_format = tink::proto::HkdfPrfKeyFormat::decode(serialized_key_format)
            .map_err(|_| TinkError::new("HkdfPrfKeyManager: invalid key format"))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("HkdfPrfKeyManager: invalid key format", e))?;

        let key_value = tink::subtle::random::get_random_bytes(key_format.key_size as usize);
        let mut sk = Vec::new();

        tink::proto::HkdfPrfKey {
            version: HKDF_PRF_KEY_VERSION,
            params: key_format.params,
            key_value,
        }
        .encode(&mut sk)
        .map_err(|e| wrap_err("HkdfPrfKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn does_support(&self, type_url: &str) -> bool {
        type_url == HKDF_PRF_TYPE_URL
    }

    fn type_url(&self) -> String {
        HKDF_PRF_TYPE_URL.to_string()
    }

    fn key_material_type(&self) -> tink::proto::key_data::KeyMaterialType {
        tink::proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`HkdfPrfKey`](tink::proto::HkdfPrfKey). It only validates the version of the
/// key because other parameters will be validated in primitive construction.
fn validate_key(key: &tink::proto::HkdfPrfKey) -> Result<(), TinkError> {
    tink::keyset::validate_key_version(key.version, HKDF_PRF_KEY_VERSION)
        .map_err(|e| wrap_err("HkdfPrfKeyManager: invalid version", e))?;
    let key_size = key.key_value.len();
    let params = match key.params.as_ref() {
        None => return Err("HkdfPrfKeyManager: no key params".into()),
        Some(p) => p,
    };
    let hash = HashType::from_i32(params.hash).unwrap_or(HashType::UnknownHash);
    subtle::validate_hkdf_prf_params(hash, key_size, &params.salt)
}

/// Validate the given [`HkdfPrfKeyFormat`](tink::proto::HkdfPrfKeyFormat).
fn validate_key_format(format: &tink::proto::HkdfPrfKeyFormat) -> Result<(), TinkError> {
    if format.params.is_none() {
        return Err("null HKDF params".into());
    }
    let params = match format.params.as_ref() {
        None => return Err("HkdfPrfKeyManager: no key format params".into()),
        Some(p) => p,
    };
    let hash = HashType::from_i32(params.hash).unwrap_or(HashType::UnknownHash);
    subtle::validate_hkdf_prf_params(hash, format.key_size as usize, &params.salt)
}
