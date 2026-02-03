// Copyright 2026 The Tink-Rust Authors
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

//! AES-EAX based implementation of the [`tink_core::Aead`] trait.

use aes::{Aes128, Aes256};
use eax::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use generic_array::typenum;
use tink_core::{utils::wrap_err, TinkError};

/// The only IV size that this implementation supports.
/// Note: The Rust [`eax`] crate only supports nonces equal to the cipher block size (16 bytes for
/// AES).
pub const AES_EAX_IV_SIZE: usize = 16;
/// The only tag size that this implementation supports.
pub const AES_EAX_TAG_SIZE: usize = 16;
/// The maximum supported plaintext size.
const MAX_AES_EAX_PLAINTEXT_SIZE: u64 = (1 << 36) - 32;

#[derive(Clone)]
enum AesEaxVariant {
    Aes128(eax::Eax<Aes128, typenum::U16>),
    Aes256(eax::Eax<Aes256, typenum::U16>),
}

/// `AesEax` is an implementation of the [`tink_core::Aead`] trait.
/// Note: This implementation only supports 16-byte IVs due to limitations in the underlying eax
/// crate.
#[derive(Clone)]
pub struct AesEax {
    cipher: AesEaxVariant,
}

impl AesEax {
    /// Return an [`AesEax`] instance.
    /// The key argument should be the AES key, either 16 or 32 bytes to select
    /// AES-128 or AES-256.
    /// The `iv_size` must be 16 bytes (128 bits).
    pub fn new(key: &[u8], iv_size: usize) -> Result<AesEax, TinkError> {
        validate_iv_size(iv_size).map_err(|e| wrap_err("AesEax", e))?;
        let cipher = match key.len() {
            16 => AesEaxVariant::Aes128(eax::Eax::new(GenericArray::from_slice(key))),
            32 => AesEaxVariant::Aes256(eax::Eax::new(GenericArray::from_slice(key))),
            l => return Err(format!("AesEax: invalid AES key size {l} (want 16, 32)").into()),
        };
        Ok(AesEax { cipher })
    }
}

impl tink_core::Aead for AesEax {
    /// Encrypt `pt` with `aad` as additional authenticated data.  The resulting ciphertext consists
    /// of two parts: (1) the IV used for encryption and (2) the actual ciphertext with tag.
    ///
    /// Note: AES-EAX implementation always returns ciphertext with 128-bit tag.
    fn encrypt(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if pt.len() as u64 > max_pt_size() {
            return Err("AesEax: plaintext too long".into());
        }
        let iv = tink_core::subtle::random::get_random_bytes(AES_EAX_IV_SIZE);
        let nonce = GenericArray::<u8, typenum::U16>::from_slice(&iv);

        let payload = Payload { msg: pt, aad };
        let ct_or = match &self.cipher {
            AesEaxVariant::Aes128(cipher) => cipher.encrypt(nonce, payload),
            AesEaxVariant::Aes256(cipher) => cipher.encrypt(nonce, payload),
        };

        let ct = ct_or.map_err(|e| wrap_err("AesEax", e))?;
        let mut ret = Vec::with_capacity(iv.len() + ct.len());
        ret.extend_from_slice(&iv);
        ret.extend_from_slice(&ct);

        Ok(ret)
    }

    /// Decrypt `ct` with `aad` as the additional authenticated data.
    fn decrypt(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ct.len() < AES_EAX_IV_SIZE + AES_EAX_TAG_SIZE {
            return Err("AesEax: ciphertext too short".into());
        }
        let nonce = GenericArray::<u8, typenum::U16>::from_slice(&ct[..AES_EAX_IV_SIZE]);

        let payload = Payload {
            msg: &ct[AES_EAX_IV_SIZE..],
            aad,
        };
        let pt_or = match &self.cipher {
            AesEaxVariant::Aes128(cipher) => cipher.decrypt(nonce, payload),
            AesEaxVariant::Aes256(cipher) => cipher.decrypt(nonce, payload),
        };

        let pt = pt_or.map_err(|e| wrap_err("AesEax", e))?;
        Ok(pt)
    }
}

/// Maximum plaintext size.
///  - 32-bit platform: (2^31 - 1) - 16 - 16
///  - 64-bit platform: 2^36 - 32
const fn max_pt_size() -> u64 {
    let x: usize = (isize::MAX as usize) - AES_EAX_IV_SIZE - AES_EAX_TAG_SIZE;
    let x: u64 = x as u64;
    if x > MAX_AES_EAX_PLAINTEXT_SIZE {
        MAX_AES_EAX_PLAINTEXT_SIZE
    } else {
        x
    }
}

/// Validate AES-EAX IV (nonce) size.
pub(crate) fn validate_iv_size(iv_size: usize) -> Result<(), TinkError> {
    if iv_size != AES_EAX_IV_SIZE {
        return Err(format!(
            "invalid AES-EAX IV size; only {AES_EAX_IV_SIZE} is supported (got {iv_size})"
        )
        .into());
    }
    Ok(())
}
