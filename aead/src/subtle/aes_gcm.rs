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

//! AES-GCM based implementation of the [`tink_core::Aead`] trait.

use aes_gcm::aead::{consts::U12, generic_array::GenericArray, Aead, NewAead, Payload};
use tink_core::{utils::wrap_err, TinkError};

/// The only IV size that this implementation supports.
pub const AES_GCM_IV_SIZE: usize = 12;
/// The only tag size that this implementation supports.
pub const AES_GCM_TAG_SIZE: usize = 16;
/// The maximum supported plaintext size.
const MAX_AES_GCM_PLAINTEXT_SIZE: u64 = (1 << 36) - 32;

#[derive(Clone)]
enum AesGcmVariant {
    Aes128(Box<aes_gcm::Aes128Gcm>),
    Aes256(Box<aes_gcm::Aes256Gcm>),
}

/// `AesGcm` is an implementation of the [`tink_core::Aead`] trait.
#[derive(Clone)]
pub struct AesGcm {
    key: AesGcmVariant,
}

impl AesGcm {
    /// Return an [`AesGcm`] instance.
    /// The key argument should be the AES key, either 16 or 32 bytes to select
    /// AES-128 or AES-256.
    pub fn new(key: &[u8]) -> Result<AesGcm, TinkError> {
        let key = match key.len() {
            16 => AesGcmVariant::Aes128(Box::new(aes_gcm::Aes128Gcm::new(
                GenericArray::from_slice(key),
            ))),
            32 => AesGcmVariant::Aes256(Box::new(aes_gcm::Aes256Gcm::new(
                GenericArray::from_slice(key),
            ))),
            l => return Err(format!("AesGcm: invalid AES key size {} (want 16, 32)", l).into()),
        };
        Ok(AesGcm { key })
    }
}

impl tink_core::Aead for AesGcm {
    /// Encrypt `pt` with `aad` as additional authenticated data.  The resulting ciphertext consists
    /// of two parts: (1) the IV used for encryption and (2) the actual ciphertext.
    ///
    /// Note: AES-GCM implementation of crypto library always returns ciphertext with 128-bit tag.
    fn encrypt(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if pt.len() as u64 > max_pt_size() {
            return Err("AesGcm: plaintext too long".into());
        }
        let iv = new_iv();
        let payload = Payload { msg: pt, aad };
        let ct = match &self.key {
            AesGcmVariant::Aes128(key) => key.encrypt(&iv, payload),
            AesGcmVariant::Aes256(key) => key.encrypt(&iv, payload),
        }
        .map_err(|e| wrap_err("AesGcm", e))?;
        let mut ret = Vec::with_capacity(iv.len() + ct.len());
        ret.extend_from_slice(&iv);
        ret.extend_from_slice(&ct);
        Ok(ret)
    }

    /// Decrypt `ct` with `aad` as the additional authenticated data.
    fn decrypt(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ct.len() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE {
            return Err("AesGcm: ciphertext too short".into());
        }
        let iv = GenericArray::from_slice(&ct[..AES_GCM_IV_SIZE]);
        let payload = Payload {
            msg: &ct[AES_GCM_IV_SIZE..],
            aad,
        };
        let pt = match &self.key {
            AesGcmVariant::Aes128(key) => key.decrypt(iv, payload),
            AesGcmVariant::Aes256(key) => key.decrypt(iv, payload),
        }
        .map_err(|e| wrap_err("AesGcm", e))?;
        Ok(pt)
    }
}

/// Create a new IV for encryption.
fn new_iv() -> GenericArray<u8, U12> {
    let iv = tink_core::subtle::random::get_random_bytes(AES_GCM_IV_SIZE);
    *GenericArray::<u8, U12>::from_slice(&iv)
}

/// Maximum plaintext size.
///  - 32-bit platform: (2^31 - 1) - 12 - 16
///  - 64-bit platform: 2^36 - 32
const fn max_pt_size() -> u64 {
    let x: usize = (isize::MAX as usize) - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    let x: u64 = x as u64;
    if x > MAX_AES_GCM_PLAINTEXT_SIZE {
        MAX_AES_GCM_PLAINTEXT_SIZE
    } else {
        x
    }
}
