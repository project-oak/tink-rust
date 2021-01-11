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

//! Key manager for AES-CTR-HMAC keys.

use crate::subtle;
use prost::Message;
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::HashType;

/// Maximal version of AES-CTR-HMAC keys.
pub const AES_CTR_HMAC_AEAD_KEY_VERSION: u32 = 0;
/// Type URL of AES-CTR-HMAC keys that Tink supports.
pub const AES_CTR_HMAC_AEAD_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
/// Minimum HMAC key size.
const MIN_HMAC_KEY_SIZE_IN_BYTES: usize = 16;
/// Minimum tag size.
const MIN_TAG_SIZE_IN_BYTES: usize = 10;

/// `AesCtrHmacAeadKeyManager` is an implementation of the [`tink_core::registry::KeyManager`]
/// trait. It generates new [`AesCtrHmacAeadKey`](tink_proto::AesCtrHmacAeadKey) keys and produces
/// new instances of [`subtle::EncryptThenAuthenticate`] that use [`subtle::AesCtr`].
#[derive(Default)]
pub(crate) struct AesCtrHmacAeadKeyManager {}

impl tink_core::registry::KeyManager for AesCtrHmacAeadKeyManager {
    /// Create an AEAD for the given serialized [`tink_proto::AesCtrHmacAeadKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("AesCtrHmacAeadKeyManager: empty key".into());
        }
        let key = tink_proto::AesCtrHmacAeadKey::decode(serialized_key)
            .map_err(|e| wrap_err("AesCtrHmacAeadKeyManager: invalid key", e))?;

        let (aes_ctr_key, aes_params) = validate_aes_key(&key)?;
        let (hmac_key, hmac_params, hash) = validate_hmac_key(&key)?;

        let ctr = subtle::AesCtr::new(&aes_ctr_key.key_value, aes_params.iv_size as usize)
            .map_err(|e| wrap_err("AesCtrHmacAeadKeyManager: cannot create new AES-CTR", e))?;
        let hmac =
            tink_mac::subtle::Hmac::new(hash, &hmac_key.key_value, hmac_params.tag_size as usize)
                .map_err(|e| {
                wrap_err(
                    "AesCtrHmacAeadKeyManager: cannot create mac primitive, error",
                    e,
                )
            })?;

        match subtle::EncryptThenAuthenticate::new(Box::new(ctr), Box::new(hmac), hmac_params.tag_size as usize) {
            Ok(p) => Ok(tink_core::Primitive::Aead(Box::new(p))),
            Err(e) => Err(wrap_err("AesCtrHmacAeadKeyManager: cannot create encrypt then authenticate primitive, error", e)),
        }
    }

    /// Create a new key according to the given serialized [`tink_proto::AesCtrHmacAeadKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("AesCtrHmacAeadKeyManager: empty key format".into());
        }
        let key_format = tink_proto::AesCtrHmacAeadKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("AesCtrHmacAeadKeyManager: invalid key format", e))?;

        let (aes_ctr_key_format, hmac_key_format) = validate_key_format(&key_format)?;
        let key = tink_proto::AesCtrHmacAeadKey {
            version: AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink_proto::AesCtrKey {
                version: AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: tink_core::subtle::random::get_random_bytes(
                    aes_ctr_key_format.key_size as usize,
                ),
                params: aes_ctr_key_format.params,
            }),
            hmac_key: Some(tink_proto::HmacKey {
                version: AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: tink_core::subtle::random::get_random_bytes(
                    hmac_key_format.key_size as usize,
                ),
                params: hmac_key_format.params,
            }),
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("AesCtrHmacAeadKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        AES_CTR_HMAC_AEAD_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Symmetric
    }
}

/// Validate and extract the AES parts of the given [`tink_proto::AesCtrHmacAeadKey`].
fn validate_aes_key(
    key: &tink_proto::AesCtrHmacAeadKey,
) -> Result<(&tink_proto::AesCtrKey, &tink_proto::AesCtrParams), TinkError> {
    tink_core::keyset::validate_key_version(key.version, AES_CTR_HMAC_AEAD_KEY_VERSION)
        .map_err(|e| wrap_err("AesCtrHmacAeadKeyManager", e))?;
    let aes_ctr_key = key
        .aes_ctr_key
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: no AES key"))?;
    tink_core::keyset::validate_key_version(aes_ctr_key.version, AES_CTR_HMAC_AEAD_KEY_VERSION)
        .map_err(|e| wrap_err("AesCtrHmacAeadKeyManager", e))?;

    // Validate `AesCtrKey`.
    let key_size = aes_ctr_key.key_value.len();
    subtle::validate_aes_key_size(key_size).map_err(|e| wrap_err("AesCtrHmacAeadKeyManager", e))?;
    let params = aes_ctr_key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: no AES key params"))?;
    if (params.iv_size as usize) < subtle::AES_CTR_MIN_IV_SIZE || params.iv_size > 16 {
        return Err(
            "AesCtrHmacAeadKeyManager: invalid AesCtrHmacAeadKey: IV size out of range".into(),
        );
    }
    Ok((aes_ctr_key, params))
}

/// Validate and extract the HMAC parts of the given [`tink_proto::AesCtrHmacAeadKey`].
fn validate_hmac_key(
    key: &tink_proto::AesCtrHmacAeadKey,
) -> Result<
    (
        &tink_proto::HmacKey,
        &tink_proto::HmacParams,
        tink_proto::HashType,
    ),
    TinkError,
> {
    let hmac_key = key
        .hmac_key
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: no HMAC key"))?;
    tink_core::keyset::validate_key_version(hmac_key.version, AES_CTR_HMAC_AEAD_KEY_VERSION)
        .map_err(|e| wrap_err("AesCtrHmacAeadKeyManager", e))?;
    let hmac_params = hmac_key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: no HMAC params"))?;
    let hash = HashType::from_i32(hmac_params.hash)
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: unknown hash"))?;

    Ok((hmac_key, hmac_params, hash))
}

/// Validate the given [`tink_proto::AesCtrHmacAeadKeyFormat`].
fn validate_key_format(
    format: &tink_proto::AesCtrHmacAeadKeyFormat,
) -> Result<(tink_proto::AesCtrKeyFormat, tink_proto::HmacKeyFormat), TinkError> {
    // Validate AesCtrKeyFormat.
    let aes_ctr_format = format
        .aes_ctr_key_format
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: no AES key format"))?;
    subtle::validate_aes_key_size(aes_ctr_format.key_size as usize)
        .map_err(|e| wrap_err("AesCtrHmacAeadKeyManager", e))?;
    let aes_params = aes_ctr_format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: no AES key params"))?;
    if (aes_params.iv_size as usize) < subtle::AES_CTR_MIN_IV_SIZE || aes_params.iv_size > 16 {
        return Err(
            "AesCtrHmacAeadKeyManager: invalid AesCtrHmacAeadKeyFormat: IV size out of range"
                .into(),
        );
    }

    // Validate HmacKeyFormat.
    let hmac_key_format = format
        .hmac_key_format
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: no HMAC key format"))?;
    if (hmac_key_format.key_size as usize) < MIN_HMAC_KEY_SIZE_IN_BYTES {
        return Err("AesCtrHmacAeadKeyManager: HMAC key_size is too small".into());
    }
    let hmac_params = hmac_key_format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("AesCtrHmacAeadKeyManager: no HMAC key params"))?;
    if (hmac_params.tag_size as usize) < MIN_TAG_SIZE_IN_BYTES {
        return Err(format!(
            "AesCtrHmacAeadKeyManager: invalid HmacParams: tag_size {} is too small",
            hmac_params.tag_size
        )
        .into());
    }

    let tag_size = match HashType::from_i32(hmac_params.hash) {
        Some(HashType::Sha1) => 20,
        Some(HashType::Sha256) => 32,
        Some(HashType::Sha512) => 64,
        _ => {
            return Err(format!(
                "AesCtrHmacAeadKeyManager: invalid HmacParams: hash_type {:?} not supported",
                hmac_params.hash
            )
            .into())
        }
    };

    if hmac_params.tag_size > tag_size {
        return Err(format!(
            "AesCtrHmacAeadKeyManager: invalid HmacParams: tag_size {} is too big for HashType {}",
            hmac_params.tag_size, hmac_params.hash
        )
        .into());
    }
    Ok((aes_ctr_format.clone(), hmac_key_format.clone()))
}
