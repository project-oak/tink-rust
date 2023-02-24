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

use std::convert::TryInto;

use ed25519_dalek::Signer as DalekSigner;
use tink_core::{utils::wrap_err, Signer, TinkError};

/// A [`Signer`] implementation for ED25519.
pub struct Ed25519Signer {
    signing_key: ed25519_dalek::SigningKey,
}

/// Manual implementation of [`Clone`].
impl Clone for Ed25519Signer {
    fn clone(&self) -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&self.signing_key.to_bytes()),
        }
    }
}

impl Ed25519Signer {
    /// Create an [`Ed25519Signer`] from the provided seed, which must be 32 bytes.
    /// RFC8032's private keys correspond to seeds here.
    pub fn new(seed: &[u8]) -> Result<Self, TinkError> {
        let secret_key: ed25519_dalek::SecretKey =
            seed.try_into().map_err(|e| wrap_err("invalid key", e))?;

        Self::new_from_keypair(ed25519_dalek::SigningKey::from_bytes(&secret_key))
    }

    pub fn new_from_keypair(signer_key: ed25519_dalek::SigningKey) -> Result<Self, TinkError> {
        Ok(Self {
            signing_key: signer_key,
        })
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, tink_core::TinkError> {
        let r = self.signing_key.sign(data);
        Ok(r.to_bytes().to_vec())
    }
}
