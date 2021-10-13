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

//! Key manager for keys wrapped by a KMS.

use tink_core::{utils::wrap_err, TinkError};
use tink_proto::prost::Message;

/// Maximal version of KMS-wrapped keys.
pub const KMS_ENVELOPE_AEAD_KEY_VERSION: u32 = 0;
/// Type URL of KMS-wrapped keys that Tink supports.
pub const KMS_ENVELOPE_AEAD_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

/// `KmsEnvelopeAeadKeyManager` is an implementation of the `tink_core::registry::KeyManager` trait.
/// It generates new [`KmsEnvelopeAeadKey`](tink_proto::KmsEnvelopeAeadKey) keys and produces new
/// instances of [`KmsEnvelopeAead`](crate::KmsEnvelopeAead).
#[derive(Default)]
pub(crate) struct KmsEnvelopeAeadKeyManager {}

impl tink_core::registry::KeyManager for KmsEnvelopeAeadKeyManager {
    /// Create a [`crate::KmsEnvelopeAead`] for the given serialized
    /// [`tink_proto::KmsEnvelopeAeadKey`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("KmsEnvelopeAeadKeyManager: empty key".into());
        }
        let key = tink_proto::KmsEnvelopeAeadKey::decode(serialized_key)
            .map_err(|e| wrap_err("KmsEnvelopeAeadKeyManager: invalid key", e))?;
        validate_key(&key)?;
        let key_params = key
            .params
            .ok_or_else(|| TinkError::new("KmsEnvelopeAeadKeyManager: missing URI"))?;
        let uri = key_params.kek_uri;
        let kms_client = tink_core::registry::get_kms_client(&uri)?;
        let backend = kms_client
            .get_aead(&uri)
            .map_err(|e| wrap_err("KmsEnvelopeAeadKeyManager: invalid aead backend", e))?;

        Ok(tink_core::Primitive::Aead(Box::new(
            crate::KmsEnvelopeAead::new(
                key_params.dek_template.ok_or_else(|| {
                    TinkError::new("KmsEnvelopeAeadKeyManager: missing DEK template")
                })?,
                backend,
            ),
        )))
    }

    /// Create a new key according to specification the given serialized
    /// [`tink_proto::KmsEnvelopeAeadKeyFormat`].
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("KmsEnvelopeAeadKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::KmsEnvelopeAeadKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("KmsEnvelopeAeadKeyManager: invalid key format", e))?;
        let key = tink_proto::KmsEnvelopeAeadKey {
            version: KMS_ENVELOPE_AEAD_KEY_VERSION,
            params: Some(key_format),
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("KmsEnvelopeAeadKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        KMS_ENVELOPE_AEAD_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::Remote
    }
}

/// Validate the given [`tink_proto::KmsEnvelopeAeadKey`].
fn validate_key(key: &tink_proto::KmsEnvelopeAeadKey) -> Result<(), TinkError> {
    tink_core::keyset::validate_key_version(key.version, KMS_ENVELOPE_AEAD_KEY_VERSION)
        .map_err(|e| wrap_err("KmsEnvelopeAeadKeyManager", e))
}
