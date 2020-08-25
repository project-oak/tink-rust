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

use signature::{Signature, Signer as RustCryptoSigner};
use tink::{utils::wrap_err, Signer, TinkError};

/// A [`Signer`] implementation for ED25519.
pub struct Ed25519Signer {
    keypair: ed25519_dalek::Keypair,
}

impl Ed25519Signer {
    /// Create an [`Ed25519Signer`] from the provided seed, which must be 32 bytes.
    /// RFC8032's private keys correspond to seeds here.
    pub fn new(seed: &[u8]) -> Result<Self, TinkError> {
        let secret_key =
            ed25519_dalek::SecretKey::from_bytes(seed).map_err(|e| wrap_err("invalid key", e))?;
        let public_key: ed25519_dalek::PublicKey = (&secret_key).into();
        Self::new_from_keypair(ed25519_dalek::Keypair {
            secret: secret_key,
            public: public_key,
        })
    }

    pub fn new_from_keypair(keypair: ed25519_dalek::Keypair) -> Result<Self, TinkError> {
        Ok(Self { keypair })
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, tink::TinkError> {
        let r = self.keypair.sign(data);
        Ok(r.as_bytes().to_vec())
    }
}
