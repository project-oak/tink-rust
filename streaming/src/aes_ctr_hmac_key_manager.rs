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
use tink::{proto::HashType, subtle::random::get_random_bytes, utils::wrap_err, TinkError};

pub const AES_CTR_HMAC_KEY_VERSION: u32 = 0;
pub const AES_CTR_HMAC_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

/// `AesCtrHmacKeyManager` is an implementation of the [`tink::registry::KeyManager`] trait.
/// It generates new [`AesCtrHmacStreamingKey`](tink::proto::AesCtrHmacStreamingKey) keys and
/// produces new instances of  [`subtle::AesCtrHmac`](crate::subtle::AesCtrHmac).
#[derive(Default)]
pub(crate) struct AesCtrHmacKeyManager {}

impl tink::registry::KeyManager for AesCtrHmacKeyManager {
    /// Create an AEAD for the given serialized [`tink::proto::AesCtrHmacStreamingKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesCtrHmacKeyManager: invalid key".into());
        }
        let key = tink::proto::AesCtrHmacStreamingKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesCtrHmacKeyManager: invalid key", e))?;
        validate_key(&key)?;

        let key_params = key
            .params
            .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: no params"))?;
        let hkdf_hash = HashType::from_i32(key_params.hkdf_hash_type)
            .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: unknown hash"))?;
        let hmac_params = key_params
            .hmac_params
            .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: no params"))?;
        let hmac_hash = HashType::from_i32(hmac_params.hash)
            .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: unknown hash"))?;

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
            Ok(p) => Ok(tink::Primitive::StreamingAead(Box::new(p))),
            Err(e) => Err(wrap_err(
                "AesCtrHmacKeyManager: cannot create new primitive",
                e,
            )),
        }
    }

    /// Create a new key according to the given serialized
    /// [`tink::proto::AesCtrHmacStreamingKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesCtrHmacKeyManager: invalid key format".into());
        }
        let key_format = tink::proto::AesCtrHmacStreamingKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("AesCtrHmacKeyManager: invalid key format", e))?;
        validate_key_format(&key_format)
            .map_err(|e| wrap_err("AesCtrHmacKeyManager: invalid key format", e))?;
        let key_params = key_format
            .params
            .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: no params"))?;
        let key = tink::proto::AesCtrHmacStreamingKey {
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

    fn key_material_type(&self) -> tink::proto::key_data::KeyMaterialType {
        tink::proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate the given [`tink::proto::AesCtrHmacStreamingKey`].
fn validate_key(key: &tink::proto::AesCtrHmacStreamingKey) -> Result<(), TinkError> {
    tink::keyset::validate_key_version(key.version, AES_CTR_HMAC_KEY_VERSION)?;
    let key_size = key.key_value.len();
    crate::subtle::validate_aes_key_size(key_size)?;
    let key_params = key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no params"))?;
    validate_params(&key_params)
}

/// Validate the given [`tink::proto::AesCtrHmacStreamingKeyFormat`].
fn validate_key_format(
    format: &tink::proto::AesCtrHmacStreamingKeyFormat,
) -> Result<(), TinkError> {
    crate::subtle::validate_aes_key_size(format.key_size as usize)?;
    let key_params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no params"))?;
    validate_params(&key_params)
}

/// Validate the given [`tink::proto::AesCtrHmacStreamingParams`].
fn validate_params(params: &tink::proto::AesCtrHmacStreamingParams) -> Result<(), TinkError> {
    crate::subtle::validate_aes_key_size(params.derived_key_size as usize)?;
    let hkdf_hash = HashType::from_i32(params.hkdf_hash_type);
    if hkdf_hash.is_none() || hkdf_hash == Some(HashType::UnknownHash) {
        return Err("unknown HKDF hash type".into());
    }
    let hmac_params = params
        .hmac_params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacKeyManager: no_params"))?;
    let hmac_hash = match HashType::from_i32(hmac_params.hash) {
        Some(HashType::UnknownHash) => return Err("unknown tag algorithm".into()),
        Some(h) => h,
        None => return Err("unknown tag algorithm".into()),
    };
    tink_mac::subtle::validate_hmac_params(
        hmac_hash,
        crate::subtle::AES_CTR_HMAC_KEY_SIZE_IN_BYTES,
        hmac_params.tag_size as usize,
    )?;
    let min_segment_size = (params.derived_key_size as usize)
        + crate::subtle::AES_CTR_HMAC_NONCE_PREFIX_SIZE_IN_BYTES
        + (hmac_params.tag_size as usize)
        + 2;
    if (params.ciphertext_segment_size as usize) < min_segment_size {
        return Err("ciphertext segment size must be at least (derived_key_size + nonce_prefix_in_bytes + tag_size_in_bytes + 2)".into());
    }
    Ok(())
}
