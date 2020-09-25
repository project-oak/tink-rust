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

//! Key manager for ChaCha20Poly1305 keys.

use crate::subtle;
use prost::Message;
use std::sync::Arc;
use tink::{utils::wrap_err, TinkError};

/// Maximal version of ChaCha20Poly1305 keys.
pub const CHA_CHA20_POLY1305_KEY_VERSION: u32 = 0;
/// Type URL of ChaCha20Poly1305 keys that Tink supports.
pub const CHA_CHA20_POLY1305_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";

/// `ChaCha20Poly1305KeyManager` is an implementation of the [`tink::registry::KeyManager`] trait.
/// It generates new [`ChaCha20Poly1305Key`](tink::proto::ChaCha20Poly1305Key) keys and produces new
/// instances of [`subtle::ChaCha20Poly1305`].
#[derive(Default)]
pub(crate) struct ChaCha20Poly1305KeyManager {}

impl tink::registry::KeyManager for ChaCha20Poly1305KeyManager {
    /// Create a [`subtle::ChaCha20Poly1305`] for the given serialized
    /// [`tink::proto::ChaCha20Poly1305Key`].
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("ChaCha20Poly1305KeyManager: invalid key".into());
        }
        let key = tink::proto::ChaCha20Poly1305Key::decode(serialized_key)
            .map_err(|e| wrap_err("ChaCha20Poly1305KeyManager: invalid key", e))?;
        validate_key(&key)?;
        match subtle::ChaCha20Poly1305::new(&key.key_value) {
            Ok(p) => Ok(tink::Primitive::Aead(Arc::new(p))),
            Err(e) => Err(wrap_err(
                "ChaCha20Poly1305KeyManager: cannot create new primitive",
                e,
            )),
        }
    }

    /// Create a new key, ignoring the specification in the given serialized key format
    /// because the key size and other params are fixed.
    fn new_key(&self, _serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        let key = new_cha_cha20_poly1305_key();
        let mut sk = Vec::new();
        key.encode(&mut sk)
            .map_err(|e| wrap_err("ChaCha20Poly1305KeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        CHA_CHA20_POLY1305_TYPE_URL
    }

    fn key_material_type(&self) -> tink::proto::key_data::KeyMaterialType {
        tink::proto::key_data::KeyMaterialType::Symmetric
    }
}

fn new_cha_cha20_poly1305_key() -> tink::proto::ChaCha20Poly1305Key {
    let key_value = tink::subtle::random::get_random_bytes(subtle::CHA_CHA20_KEY_SIZE);
    tink::proto::ChaCha20Poly1305Key {
        version: CHA_CHA20_POLY1305_KEY_VERSION,
        key_value,
    }
}

/// Validate the given [`tink::proto::ChaCha20Poly1305Key`].
fn validate_key(key: &tink::proto::ChaCha20Poly1305Key) -> Result<(), TinkError> {
    tink::keyset::validate_key_version(key.version, CHA_CHA20_POLY1305_KEY_VERSION)
        .map_err(|e| wrap_err("ChaCha20Poly1305KeyManager", e))?;
    let key_size = key.key_value.len();
    if key_size != subtle::CHA_CHA20_KEY_SIZE {
        return Err(format!(
            "ChaCha20Poly1305KeyManager: keySize != {}",
            subtle::CHA_CHA20_KEY_SIZE,
        )
        .into());
    }
    Ok(())
}
