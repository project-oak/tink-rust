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

//! ChaCha20 Poly1305 implementation of AEAD.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit,
};
use tink_core::{utils::wrap_err, TinkError};

/// Size of a ChaCh20 key in bytes.
pub const CHA_CHA20_KEY_SIZE: usize = 32;
/// Size of a ChaCh20 nonce in bytes.
pub const CHA_CHA20_NONCE_SIZE: usize = 12;
/// Size of a Poly1305 tag in bytes.
const POLY1305_TAG_SIZE: usize = 16;

/// `ChaCha20Poly1305` is an implementation of the [`tink_core::Aead`] trait.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: chacha20poly1305::Key,
}

impl ChaCha20Poly1305 {
    /// Return an `ChaCha20Poly1305` instance.
    /// The `key` argument should be a 32-byte key.
    pub fn new(key: &[u8]) -> Result<ChaCha20Poly1305, TinkError> {
        if key.len() != CHA_CHA20_KEY_SIZE {
            return Err("ChaCha20Poly1305: bad key length".into());
        }

        Ok(ChaCha20Poly1305 {
            key: chacha20poly1305::Key::clone_from_slice(key),
        })
    }
}

impl tink_core::Aead for ChaCha20Poly1305 {
    /// Encrypt `pt` with `aad` as additional
    /// authenticated data. The resulting ciphertext consists of two parts:
    /// (1) the nonce used for encryption and (2) the actual ciphertext.
    fn encrypt(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if pt.len() > (isize::MAX as usize) - CHA_CHA20_NONCE_SIZE - POLY1305_TAG_SIZE {
            return Err("ChaCha20Poly1305: plaintext too long".into());
        }
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&self.key);
        let n = new_nonce();
        let ct = cipher
            .encrypt(&n, Payload { msg: pt, aad })
            .map_err(|e| wrap_err("ChaCha20Poly1305", e))?;

        let mut ret = Vec::with_capacity(n.len() + ct.len());
        ret.extend_from_slice(&n);
        ret.extend_from_slice(&ct);
        Ok(ret)
    }

    /// Decrypt `ct` with `aad` as the additional authenticated data.
    fn decrypt(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ct.len() < CHA_CHA20_NONCE_SIZE + POLY1305_TAG_SIZE {
            return Err("ChaCha20pPly1305: ciphertext too short".into());
        }

        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&self.key);
        let n = chacha20poly1305::Nonce::from_slice(&ct[..CHA_CHA20_NONCE_SIZE]);
        cipher
            .decrypt(
                n,
                Payload {
                    msg: &ct[CHA_CHA20_NONCE_SIZE..],
                    aad,
                },
            )
            .map_err(|e| wrap_err("ChaCha20Poly1305", e))
    }
}

/// Create a new nonce for encryption.
fn new_nonce() -> chacha20poly1305::Nonce {
    let iv = tink_core::subtle::random::get_random_bytes(CHA_CHA20_NONCE_SIZE);
    *chacha20poly1305::Nonce::from_slice(&iv)
}
