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

//! General AEAD implementation combining an `IndCpaCipher` with a `tink_core::Mac`

use super::IndCpaCipher;
use tink_core::{utils::wrap_err, TinkError};

/// `EncryptThenAuthenticate` performs an encrypt-then-MAC operation on plaintext
/// and additional authenticated data (aad). The MAC is computed over (aad ||
/// ciphertext || size of aad). This implementation is based on
/// <http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05>.
pub struct EncryptThenAuthenticate {
    ind_cpa_cipher: Box<dyn IndCpaCipher>,
    mac: Box<dyn tink_core::Mac>,
    tag_size: usize,
}

/// Manual implementation of [`Clone`] relying on the trait bounds for
/// primitives to provide `.box_clone()` methods.
impl Clone for EncryptThenAuthenticate {
    fn clone(&self) -> Self {
        Self {
            ind_cpa_cipher: self.ind_cpa_cipher.box_clone(),
            mac: self.mac.box_clone(),
            tag_size: self.tag_size,
        }
    }
}

const MIN_TAG_SIZE_IN_BYTES: usize = 10;

impl EncryptThenAuthenticate {
    /// Return a new instance of EncryptThenAuthenticate.
    pub fn new(
        ind_cpa_cipher: Box<dyn IndCpaCipher>,
        mac: Box<dyn tink_core::Mac>,
        tag_size: usize,
    ) -> Result<EncryptThenAuthenticate, TinkError> {
        if tag_size < MIN_TAG_SIZE_IN_BYTES {
            return Err("EncryptThenAuthenticate: tag size too small".into());
        }
        Ok(EncryptThenAuthenticate {
            ind_cpa_cipher,
            mac,
            tag_size,
        })
    }
}

impl tink_core::Aead for EncryptThenAuthenticate {
    /// Encrypt `plaintext` with `additional_data` as additional authenticated
    /// data. The resulting ciphertext allows for checking authenticity and
    /// integrity of additional data, but does not guarantee its secrecy.
    ///
    /// The plaintext is encrypted with an [`IndCpaCipher`], then MAC is computed over
    /// (additional_data || ciphertext || n) where n is additional_data's length
    /// in bits represented as a 64-bit bigendian unsigned integer. The final
    /// ciphertext format is (IND-CPA ciphertext || mac).
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        let mut ciphertext = self
            .ind_cpa_cipher
            .encrypt(plaintext)
            .map_err(|e| wrap_err("EncryptThenAuthenticate", e))?;

        // Authenticate the following data:
        // additional_data || payload || aad_size_in_bits
        let mut to_auth_data = Vec::with_capacity(additional_data.len() + ciphertext.len() + 8);
        to_auth_data.extend_from_slice(additional_data);
        to_auth_data.extend_from_slice(&ciphertext);
        let aad_size_in_bits: u64 = (additional_data.len() as u64)
            .checked_mul(8)
            .ok_or_else(|| TinkError::new("EncryptThenAuthenticate: additional data too long"))?;
        to_auth_data.extend_from_slice(&aad_size_in_bits.to_be_bytes());

        let tag = self
            .mac
            .compute_mac(&to_auth_data)
            .map_err(|e| wrap_err("EncryptThenAuthenticate", e))?;
        if tag.len() != self.tag_size {
            return Err("EncryptThenAuthenticate: invalid tag size".into());
        }

        // Put the tag at the end of the ciphertext.
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    /// Decrypt `ciphertext` with `additional_data` as additional authenticated
    /// data.
    fn decrypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ciphertext.len() < self.tag_size {
            return Err("EncryptThenAuthenticate: ciphertext too short".into());
        }

        // payload contains everything except the tag at the end.
        let payload = &ciphertext[..(ciphertext.len() - self.tag_size)];

        // Authenticate the following data:
        // additional_data || payload || aad_size_in_bits
        let mut to_auth_data = Vec::with_capacity(additional_data.len() + payload.len() + 8);
        to_auth_data.extend_from_slice(additional_data);
        to_auth_data.extend_from_slice(payload);
        let aad_size_in_bits: u64 = (additional_data.len() as u64)
            .checked_mul(8)
            .ok_or_else(|| TinkError::new("EncryptThenAuthenticate: additional data too long"))?;
        to_auth_data.extend_from_slice(&aad_size_in_bits.to_be_bytes());

        // Verify against the tag at the end of the ciphertext.
        self.mac
            .verify_mac(
                &ciphertext[(ciphertext.len() - self.tag_size)..],
                &to_auth_data,
            )
            .map_err(|e| wrap_err("EncryptThenAuthenticate", e))?;

        let plaintext = self
            .ind_cpa_cipher
            .decrypt(payload)
            .map_err(|e| wrap_err("EncryptThenAuthenticate", e))?;

        Ok(plaintext)
    }
}
