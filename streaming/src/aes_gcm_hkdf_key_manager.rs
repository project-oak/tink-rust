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

//! Key manager for streaming AES-GCM-HKDF.

use crate::subtle;
use std::convert::TryFrom;
use tink_core::{subtle::random::get_random_bytes, utils::wrap_err, TinkError};
use tink_proto::{prost::Message, HashType};

/// Maximal version of AES-GCM-HKDF keys.
pub const AES_GCM_HKDF_KEY_VERSION: u32 = 0;
/// Type URL of AES-GCM-HKDF keys that Tink supports.
pub const AES_GCM_HKDF_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

/// [`AesGcmHkdfKeyManager`] is an implementation of the [`tink_core::registry::KeyManager`] trait.
/// It generates new AESGCM_HKDFKey keys and produces new instances of [`subtle::AesGcmHkdf`].
#[derive(Default)]
pub(crate) struct AesGcmHkdfKeyManager {}

impl tink_core::registry::KeyManager for AesGcmHkdfKeyManager {
    /// Create an AEAD for the given serialized [`tink_proto::AesGcmHkdfStreamingKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesGcmHkdfKeyManager: invalid key".into());
        }
        let key = tink_proto::AesGcmHkdfStreamingKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesGcmHkdfKeyManager: invalid key", e))?;
        let (key_params, hkdf_hash) =
            validate_key(&key).map_err(|e| wrap_err("AesGcmHkdfKeyManager", e))?;
        match subtle::AesGcmHkdf::new(
            &key.key_value,
            hkdf_hash,
            key_params.derived_key_size as usize,
            key_params.ciphertext_segment_size as usize,
            // no first segment offset
            0,
        ) {
            Ok(p) => Ok(tink_core::Primitive::StreamingAead(Box::new(p))),
            Err(e) => Err(wrap_err(
                "AesGcmHkdfKeyManager: cannot create new primitive",
                e,
            )),
        }
    }

    /// Create a new key according to specification in the given serialized
    /// [`tink_proto::AesGcmHkdfStreamingKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesGcm_HkdfKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::AesGcmHkdfStreamingKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("AesGcmHkdfKeyManager: invalid key format", e))?;
        let key_params =
            validate_key_format(&key_format).map_err(|e| wrap_err("AesGcmHkdfKeyManager", e))?;
        let key = tink_proto::AesGcmHkdfStreamingKey {
            version: AES_GCM_HKDF_KEY_VERSION,
            key_value: get_random_bytes(key_format.key_size as usize),
            params: Some(key_params),
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("AesGcmHkdfKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }
    fn type_url(&self) -> &'static str {
        AES_GCM_HKDF_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`tink_proto::AesGcmHkdfStreamingKey`].
fn validate_key(
    key: &tink_proto::AesGcmHkdfStreamingKey,
) -> Result<(tink_proto::AesGcmHkdfStreamingParams, HashType), TinkError> {
    tink_core::keyset::validate_key_version(key.version, AES_GCM_HKDF_KEY_VERSION)?;
    crate::subtle::validate_aes_key_size(key.key_value.len())?;
    let key_params = key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no key params"))?;
    let hkdf_hash = validate_params(key_params)?;
    Ok((*key_params, hkdf_hash))
}

/// Validate the given [`tink_proto::AesGcmHkdfStreamingKeyFormat`].
fn validate_key_format(
    format: &tink_proto::AesGcmHkdfStreamingKeyFormat,
) -> Result<tink_proto::AesGcmHkdfStreamingParams, TinkError> {
    crate::subtle::validate_aes_key_size(format.key_size as usize)?;
    let format_params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no format params"))?;
    validate_params(format_params).map_err(|e| wrap_err("AesGcmHkdfKeyManager", e))?;
    Ok(*format_params)
}

/// Validate the given [`tink_proto::AesGcmHkdfStreamingParams`].
fn validate_params(params: &tink_proto::AesGcmHkdfStreamingParams) -> Result<HashType, TinkError> {
    crate::subtle::validate_aes_key_size(params.derived_key_size as usize)?;
    let hkdf_hash = match HashType::try_from(params.hkdf_hash_type) {
        Ok(HashType::UnknownHash) => return Err("unknown HKDF hash type".into()),
        Ok(h) => h,
        Err(_) => return Err("unknown HKDF hash type".into()),
    };
    let min_segment_size = (params.derived_key_size as usize)
        + subtle::AES_GCM_HKDF_NONCE_PREFIX_SIZE_IN_BYTES
        + subtle::AES_GCM_HKDF_TAG_SIZE_IN_BYTES
        + 2;
    if (params.ciphertext_segment_size as usize) < min_segment_size {
        return Err("ciphertext segment_size must be at least (derivedKeySize + noncePrefixInBytes + tagSizeInBytes + 2)".into());
    }
    Ok(hkdf_hash)
}
