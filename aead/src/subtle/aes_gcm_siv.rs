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

//! AES-GCM-SIV based implementation of the [`tink::Aead`] trait.

use aes_gcm_siv::aead::{consts::U12, generic_array::GenericArray, Aead, NewAead, Payload};
use tink::{utils::wrap_err, TinkError};

/// The only IV size that this implementation supports.
pub const AES_GCM_SIV_IV_SIZE: usize = 12;
/// The only tag size that this implementation supports.
pub const AES_GCM_SIV_TAG_SIZE: usize = 16;
// TODO(#47): check whether this limit is needed and correct.
/// The maximum supported plaintext size.
const MAX_AES_GCM_SIV_PLAINTEXT_SIZE: usize = (1 << 36) - 32;

#[derive(Clone)]
enum AesGcmSivVariant {
    Aes128(Box<aes_gcm_siv::Aes128GcmSiv>),
    Aes256(Box<aes_gcm_siv::Aes256GcmSiv>),
}

/// `AesGcmSiv` is an implementation of the [`tink::Aead`] trait.
#[derive(Clone)]
pub struct AesGcmSiv {
    key: AesGcmSivVariant,
}

impl AesGcmSiv {
    /// Return an [`AesGcmSiv`] instance.
    /// The key argument should be the AES key, either 16 or 32 bytes to select
    /// AES-128 or AES-256.
    pub fn new(key: &[u8]) -> Result<AesGcmSiv, TinkError> {
        let key = match key.len() {
            16 => AesGcmSivVariant::Aes128(Box::new(aes_gcm_siv::Aes128GcmSiv::new(
                GenericArray::from_slice(key),
            ))),
            32 => AesGcmSivVariant::Aes256(Box::new(aes_gcm_siv::Aes256GcmSiv::new(
                GenericArray::from_slice(key),
            ))),
            l => return Err(format!("AesGcmSiv: invalid AES key size {} (want 16, 32)", l).into()),
        };
        Ok(AesGcmSiv { key })
    }
}

impl tink::Aead for AesGcmSiv {
    /// Encrypt `pt` with `aad` as additional authenticated data.  The resulting ciphertext consists
    /// of two parts: (1) the IV used for encryption and (2) the actual ciphertext.
    ///
    /// Note: AES-GCM-SIV implementation of crypto library always returns ciphertext with 128-bit
    /// tag.
    fn encrypt(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if pt.len() > max_pt_size() {
            return Err("AesGcmSiv: plaintext too long".into());
        }
        let iv = new_iv();
        let payload = Payload { msg: pt, aad };
        let ct = match &self.key {
            AesGcmSivVariant::Aes128(key) => key.encrypt(&iv, payload),
            AesGcmSivVariant::Aes256(key) => key.encrypt(&iv, payload),
        }
        .map_err(|e| wrap_err("AesGcmSiv", e))?;
        let mut ret = Vec::with_capacity(iv.len() + ct.len());
        ret.extend_from_slice(&iv);
        ret.extend_from_slice(&ct);
        Ok(ret)
    }

    /// Decrypt `ct` with `aad` as the additional authenticated data.
    fn decrypt(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ct.len() < AES_GCM_SIV_IV_SIZE + AES_GCM_SIV_TAG_SIZE {
            return Err("AesGcmSiv: ciphertext too short".into());
        }
        let iv = GenericArray::from_slice(&ct[..AES_GCM_SIV_IV_SIZE]);
        let payload = Payload {
            msg: &ct[AES_GCM_SIV_IV_SIZE..],
            aad,
        };
        let pt = match &self.key {
            AesGcmSivVariant::Aes128(key) => key.decrypt(iv, payload),
            AesGcmSivVariant::Aes256(key) => key.decrypt(iv, payload),
        }
        .map_err(|e| wrap_err("AesGcmSiv", e))?;
        Ok(pt)
    }
}

/// Create a new IV for encryption.
fn new_iv() -> GenericArray<u8, U12> {
    let iv = tink::subtle::random::get_random_bytes(AES_GCM_SIV_IV_SIZE);
    *GenericArray::<u8, U12>::from_slice(&iv)
}

/// Maximum plaintext size.
fn max_pt_size() -> usize {
    let x = (isize::MAX as usize) - AES_GCM_SIV_IV_SIZE - AES_GCM_SIV_TAG_SIZE;
    std::cmp::min(x, MAX_AES_GCM_SIV_PLAINTEXT_SIZE)
}
