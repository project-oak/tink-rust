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

//! Key manager for ED25519 verification keys.

use tink_core::{utils::wrap_err, TinkError};
use tink_proto::prost::Message;

/// Maximal version of ED25519 keys.
pub const ED25519_VERIFIER_KEY_VERSION: u32 = 0;
/// Type URL of ED25519 keys that Tink supports.
pub const ED25519_VERIFIER_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";

/// An implementation of the [`tink_core::registry::KeyManager`] trait.
/// It doesn't support key generation.
#[derive(Default)]
pub(crate) struct Ed25519VerifierKeyManager {}

impl tink_core::registry::KeyManager for Ed25519VerifierKeyManager {
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("Ed25519VerifierKeyManager: invalid key".into());
        }
        let key = tink_proto::Ed25519PublicKey::decode(serialized_key)
            .map_err(|e| wrap_err("Ed25519VerifierKeyManager: invalid key", e))?;
        validate_ed25519_public_key(&key).map_err(|e| wrap_err("Ed25519VerifierKeyManager", e))?;

        match crate::subtle::Ed25519Verifier::new(&key.key_value) {
            Ok(p) => Ok(tink_core::Primitive::Verifier(Box::new(p))),
            Err(e) => Err(wrap_err("Ed25519VerifierKeyManager: invalid key", e)),
        }
    }

    fn new_key(&self, _serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        Err("Ed25519VerifierKeyManager: not implemented".into())
    }

    fn type_url(&self) -> &'static str {
        ED25519_VERIFIER_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::AsymmetricPublic
    }
}

/// Validate the given [`Ed25519PublicKey`](tink_proto::Ed25519PublicKey).
pub(crate) fn validate_ed25519_public_key(
    key: &tink_proto::Ed25519PublicKey,
) -> Result<(), TinkError> {
    tink_core::keyset::validate_key_version(key.version, ED25519_VERIFIER_KEY_VERSION)?;

    if key.key_value.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
        Err(format!(
            "invalid key length, required: {}",
            ed25519_dalek::PUBLIC_KEY_LENGTH
        )
        .into())
    } else {
        Ok(())
    }
}
