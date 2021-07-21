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

//! Key manager for ED25519 signing keys.

use alloc::{boxed::Box, format, string::ToString, vec::Vec};
use prost::Message;
use tink_core::{utils::wrap_err, TinkError};

/// Maximal version of ED25519 keys.
pub const ED25519_SIGNER_KEY_VERSION: u32 = 0;
/// Type URL of ED25519 keys that Tink supports.
pub const ED25519_SIGNER_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

/// An implementation of the [`tink_core::registry::KeyManager`] trait.
/// It generates new ED25519PrivateKeys and produces new instances of
/// [`crate::subtle::Ed25519Signer`].
#[derive(Default)]
pub(crate) struct Ed25519SignerKeyManager {}

impl tink_core::registry::KeyManager for Ed25519SignerKeyManager {
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("Ed25519SignerKeyManager: invalid key".into());
        }
        let key = tink_proto::Ed25519PrivateKey::decode(serialized_key)
            .map_err(|e| wrap_err("Ed25519SignerKeyManager: invalid key", e))?;
        validate_key(&key)?;

        match crate::subtle::Ed25519Signer::new(&key.key_value) {
            Ok(p) => Ok(tink_core::Primitive::Signer(Box::new(p))),
            Err(e) => Err(wrap_err("Ed25519SignerKeyManager: invalid key", e)),
        }
    }

    fn new_key(&self, _serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        let mut csprng = rand::rngs::OsRng {};
        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);

        let public_proto = tink_proto::Ed25519PublicKey {
            version: ED25519_SIGNER_KEY_VERSION,
            key_value: keypair.public.as_bytes().to_vec(),
        };
        let key = tink_proto::Ed25519PrivateKey {
            version: ED25519_SIGNER_KEY_VERSION,
            public_key: Some(public_proto),
            key_value: keypair.secret.as_bytes().to_vec(),
        };
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("Ed25519SignerKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        ED25519_SIGNER_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::AsymmetricPrivate
    }

    fn supports_private_keys(&self) -> bool {
        true
    }

    fn public_key_data(
        &self,
        serialized_priv_key: &[u8],
    ) -> Result<tink_proto::KeyData, TinkError> {
        let key = tink_proto::Ed25519PrivateKey::decode(serialized_priv_key)
            .map_err(|e| wrap_err("Ed25519SignerKeyManager: invalid key", e))?;
        let mut serialized_pub_key = Vec::new();
        key.public_key
            .ok_or_else(|| TinkError::new("Ed25519SignerKeyManager: invalid key"))?
            .encode(&mut serialized_pub_key)
            .map_err(|e| wrap_err("Ed25519SignerKeyManager: invalid key", e))?;
        Ok(tink_proto::KeyData {
            type_url: crate::ED25519_VERIFIER_TYPE_URL.to_string(),
            value: serialized_pub_key,
            key_material_type: tink_proto::key_data::KeyMaterialType::AsymmetricPublic as i32,
        })
    }
}

/// Validate the given [`Ed25519PrivateKey`](tink_proto::Ed25519PrivateKey).
fn validate_key(key: &tink_proto::Ed25519PrivateKey) -> Result<(), TinkError> {
    tink_core::keyset::validate_key_version(key.version, ED25519_SIGNER_KEY_VERSION)
        .map_err(|e| wrap_err("Ed25519SignerKeyManager", e))?;

    if key.key_value.len() != ed25519_dalek::SECRET_KEY_LENGTH {
        return Err(format!(
            "Ed25519SignerKeyManager: invalid key length: {}",
            key.key_value.len()
        )
        .into());
    }
    let pub_key = key
        .public_key
        .as_ref()
        .ok_or_else(|| TinkError::new("Ed25519SignerKeyManager: no public key"))?;
    crate::validate_ed25519_public_key(pub_key)
}
