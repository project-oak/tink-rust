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

use signature::{Signature, Verifier as RustCryptoVerifier};
use tink_core::{utils::wrap_err, TinkError};

/// A [`tink_core::Verifier`] for ED25519.
#[derive(Clone)]
pub struct Ed25519Verifier {
    public_key: ed25519_dalek::PublicKey,
}

impl Ed25519Verifier {
    /// Create a new instance of `Ed25519Verifier` from a compressed point on the curve.
    pub fn new(pub_key: &[u8]) -> Result<Self, TinkError> {
        // The docs for [`ed25519_dalek::PublicKey`] state that the caller is responsible
        // for ensuring that `pub_key` is a compressed point on the curve; however, the
        // implementation does appear to check this.
        let public_key = ed25519_dalek::PublicKey::from_bytes(pub_key)
            .map_err(|e| wrap_err("Ed25519Verifier: invalid key", e))?;
        Self::new_from_public_key(public_key)
    }

    pub fn new_from_public_key(public_key: ed25519_dalek::PublicKey) -> Result<Self, TinkError> {
        Ok(Self { public_key })
    }
}

impl tink_core::Verifier for Ed25519Verifier {
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<(), tink_core::TinkError> {
        if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
            return Err(format!(
                "the length of the signature is not {}",
                ed25519_dalek::SIGNATURE_LENGTH
            )
            .into());
        }
        let s = <ed25519_dalek::Signature as Signature>::from_bytes(signature)
            .map_err(|e| wrap_err("invalid signature", e))?;
        self.public_key
            .verify(data, &s)
            .map_err(|_| TinkError::new("Ed25519Verifier: invalid signature"))
    }
}
