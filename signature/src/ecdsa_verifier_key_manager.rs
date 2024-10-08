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

//! Key manager for ECDSA verification keys.

use tink_core::{utils::wrap_err, TinkError};
use tink_proto::prost::Message;

/// Maximal version of ECDSA keys.
pub const ECDSA_VERIFIER_KEY_VERSION: u32 = 0;
/// Type URL of ECDSA keys that Tink supports.
pub const ECDSA_VERIFIER_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";

/// An implementation of the [`tink_core::registry::KeyManager`] trait.
/// It doesn't support key generation.
#[derive(Default)]
pub(crate) struct EcdsaVerifierKeyManager {}

impl tink_core::registry::KeyManager for EcdsaVerifierKeyManager {
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("EcdsaVerifierKeyManager: invalid key".into());
        }
        let key = tink_proto::EcdsaPublicKey::decode(serialized_key)
            .map_err(|e| wrap_err("EcdsaVerifierKeyManager: invalid key", e))?;
        let params =
            validate_ecdsa_public_key(&key).map_err(|e| wrap_err("EcdsaVerifierKeyManager", e))?;

        let (hash, curve, encoding) = crate::get_ecdsa_param_ids(&params);
        match crate::subtle::EcdsaVerifier::new(hash, curve, encoding, &key.x, &key.y) {
            Ok(p) => Ok(tink_core::Primitive::Verifier(Box::new(p))),
            Err(e) => Err(wrap_err("EcdsaVerifierKeyManager: invalid key", e)),
        }
    }

    fn new_key(&self, _serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        Err("EcdsaVerifierKeyManager: not implemented".into())
    }

    fn type_url(&self) -> &'static str {
        ECDSA_VERIFIER_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::AsymmetricPublic
    }
}

/// Validate the given [`EcdsaPublicKey`](tink_proto::EcdsaPublicKey) and return
/// the parameters.
pub(crate) fn validate_ecdsa_public_key(
    key: &tink_proto::EcdsaPublicKey,
) -> Result<tink_proto::EcdsaParams, TinkError> {
    tink_core::keyset::validate_key_version(key.version, ECDSA_VERIFIER_KEY_VERSION)?;
    let params = key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no public key parameters"))?;
    let (hash, curve, encoding) = crate::get_ecdsa_param_ids(params);
    crate::subtle::validate_ecdsa_params(hash, curve, encoding)?;
    Ok(*params)
}
