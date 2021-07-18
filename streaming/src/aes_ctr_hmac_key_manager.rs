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

//! Key manager for streaming AES-CTR-HMAC keys.

use prost::Message;
use tink_core::{subtle::random::get_random_bytes, utils::wrap_err, TinkError};
use tink_proto::HashType;

/// Maximal version of AES-CTR-HMAC keys.
pub const AES_CTR_HMAC_KEY_VERSION: u32 = 0;
/// Type URL of AES-CTR-HMAC keys that Tink supports.
pub const AES_CTR_HMAC_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

/// `AesCtrHmacKeyManager` is an implementation of the [`tink_core::registry::KeyManager`] trait.
/// It generates new [`AesCtrHmacStreamingKey`](tink_proto::AesCtrHmacStreamingKey) keys and
/// produces new instances of  [`subtle::AesCtrHmac`](crate::subtle::AesCtrHmac).
#[derive(Default)]
pub(crate) struct AesCtrHmacKeyManager {}

impl tink_core::registry::KeyManager for AesCtrHmacKeyManager {
    /// Create an AEAD for the given serialized [`tink_proto::AesCtrHmacStreamingKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesCtrHmacKeyManager: invalid key".into());
        }
        let key = tink_proto::AesCtrHmacStreamingKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesCtrHmacKeyManager: invalid key", e))?;

        let key_params = validate_key(&key)?;
        let (hmac_params, hkdf_hash, hmac_hash) = validate_params(&key_params)?;
        match crate::subtle::AesCtrHmac::new(
            &key.key_value,
            hkdf_hash,
            key_params.derived_key_size as usize,
            hmac_hash,
            hmac_params.tag_size as usize,
            key_params.ciphertext_segment_size as usize,
            // No first segment offset.
            0,
        ) {
            Ok(p) => Ok(tink_core::Primitive::StreamingAead(Box::new(p))),
            Err(e) => Err(wrap_err(
                "AesCtrHmacKeyManager: cannot create new primitive",
                e,
            )),
        }
    }

    /// Create a new key according to the given serialized
    /// [`tink_proto::AesCtrHmacStreamingKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesCtrHmacKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::AesCtrHmacStreamingKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("AesCtrHmacKeyManager: invalid key format", e))?;
        let key_params = validate_key_format(&key_format)?;
        let key = tink_proto::AesCtrHmacStreamingKey {
            version: AES_CTR_HMAC_KEY_VERSION,
            key_value: get_random_bytes(key_format.key_size as usize),
            params: Some(key_params),
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("AesCtrHmacKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        AES_CTR_HMAC_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`tink_proto::AesCtrHmacStreamingKey`].
fn validate_key(
    key: &tink_proto::AesCtrHmacStreamingKey,
) -> Result<tink_proto::AesCtrHmacStreamingParams, TinkError> {
    tink_core::keyset::validate_key_version(key.version, AES_CTR_HMAC_KEY_VERSION)?;
    crate::subtle::validate_aes_key_size(key.key_value.len())?;
    let key_params = key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: no params"))?;
    Ok(key_params.clone())
}

/// Validate the given [`tink_proto::AesCtrHmacStreamingKeyFormat`].
fn validate_key_format(
    format: &tink_proto::AesCtrHmacStreamingKeyFormat,
) -> Result<tink_proto::AesCtrHmacStreamingParams, TinkError> {
    tink_core::keyset::validate_key_version(format.version, AES_CTR_HMAC_KEY_VERSION)?;
    crate::subtle::validate_aes_key_size(format.key_size as usize)?;
    let key_params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: no params"))?;
    validate_params(key_params)?;
    Ok(key_params.clone())
}

/// Validate the given [`tink_proto::AesCtrHmacStreamingParams`].
fn validate_params(
    params: &tink_proto::AesCtrHmacStreamingParams,
) -> Result<(tink_proto::HmacParams, HashType, HashType), TinkError> {
    crate::subtle::validate_aes_key_size(params.derived_key_size as usize)?;
    let hkdf_hash = match HashType::from_i32(params.hkdf_hash_type) {
        Some(HashType::UnknownHash) => return Err("AesCtrHmacKeyManager: unknown HKDF hash".into()),
        Some(h) => h,
        None => return Err("AesCtrHmacKeyManager: unknown HKDF hash".into()),
    };
    let hmac_params = params
        .hmac_params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: no HMAC params"))?;
    let hmac_hash = match HashType::from_i32(hmac_params.hash) {
        Some(HashType::UnknownHash) => {
            return Err("AesCtrHmacKeyManager: unknown tag algorithm".into())
        }
        Some(h) => h,
        None => return Err("AesCtrHmacKeyManager: unknown tag algorithm".into()),
    };
    tink_mac::subtle::validate_hmac_params(
        hmac_hash,
        crate::subtle::AES_CTR_HMAC_KEY_SIZE_IN_BYTES,
        hmac_params.tag_size as usize,
    )
    .map_err(|e| wrap_err("AesCtrHmacKeyManager", e))?;
    let min_segment_size = (params.derived_key_size as usize)
        + crate::subtle::AES_CTR_HMAC_NONCE_PREFIX_SIZE_IN_BYTES
        + (hmac_params.tag_size as usize)
        + 2;
    if (params.ciphertext_segment_size as usize) < min_segment_size {
        return Err("AesCtrHmacKeyManager: ciphertext segment size must be at least (derived_key_size + nonce_prefix_in_bytes + tag_size_in_bytes + 2)".into());
    }
    Ok((hmac_params.clone(), hkdf_hash, hmac_hash))
}
