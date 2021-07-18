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

//! AES-CTR implementation of [`IndCpaCipher`](super::IndCpaCipher).

use super::IndCpaCipher;
use aes::{
    cipher::{consts::U16, generic_array::GenericArray, FromBlockCipher, StreamCipher},
    NewBlockCipher,
};
use alloc::{format, vec::Vec};
use tink_core::{utils::wrap_err, TinkError};

/// The minimum IV size that this implementation supports.
pub const AES_CTR_MIN_IV_SIZE: usize = 12;

pub const AES_BLOCK_SIZE_IN_BYTES: usize = 16;

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum AesCtrVariant {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

/// `AesCtr` is an implementation of AEAD interface.
#[derive(Clone)]
pub struct AesCtr {
    key: AesCtrVariant,
    pub iv_size: usize,
}

impl AesCtr {
    /// Return an `AesCtr` instance.  The key argument should be the AES key, either 16 or 32 bytes
    /// to select AES-128 or AES-256.  `iv_size` specifies the size of the IV in bytes.
    pub fn new(key: &[u8], iv_size: usize) -> Result<AesCtr, TinkError> {
        let key_size = key.len();
        super::validate_aes_key_size(key_size).map_err(|e| wrap_err("AesCtr", e))?;
        if !(AES_CTR_MIN_IV_SIZE..=AES_BLOCK_SIZE_IN_BYTES).contains(&iv_size) {
            return Err(format!("AesCtr: invalid IV size: {}", iv_size).into());
        }
        let key = match key.len() {
            16 => {
                AesCtrVariant::Aes128(
                    aes::Aes128::new_from_slice(key).unwrap(/* safe: len checked */),
                )
            }
            32 => {
                AesCtrVariant::Aes256(
                    aes::Aes256::new_from_slice(key).unwrap(/* safe: len checked */),
                )
            }
            l => return Err(format!("AesCtr: invalid AES key size {} (want 16, 32)", l).into()),
        };
        Ok(AesCtr { key, iv_size })
    }

    /// Return the length of the key.
    pub fn key_len(&self) -> usize {
        match &self.key {
            AesCtrVariant::Aes128(_) => 16,
            AesCtrVariant::Aes256(_) => 32,
        }
    }

    /// Create a new IV for encryption.
    fn new_iv(&self) -> GenericArray<u8, U16> {
        let mut padded_iv = [0; AES_BLOCK_SIZE_IN_BYTES];
        let iv = tink_core::subtle::random::get_random_bytes(self.iv_size);
        padded_iv[..iv.len()].copy_from_slice(&iv);
        padded_iv.into()
    }
}

impl IndCpaCipher for AesCtr {
    /// Encrypt plaintext using AES in CTR mode.
    /// The resulting ciphertext consists of two parts:
    /// (1) the IV used for encryption and (2) the actual ciphertext.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, TinkError> {
        if plaintext.len() > ((isize::MAX as usize) - self.iv_size) {
            return Err("AesCtr: plaintext too long".into());
        }
        let iv = self.new_iv();
        let mut ciphertext = Vec::with_capacity(self.iv_size + plaintext.len());
        ciphertext.extend_from_slice(&iv[..self.iv_size]);
        ciphertext.extend_from_slice(plaintext);
        match &self.key {
            AesCtrVariant::Aes128(key) => {
                let mut stream = aes::Aes128Ctr::from_block_cipher(key.clone(), &iv);
                stream.apply_keystream(&mut ciphertext[self.iv_size..]);
            }
            AesCtrVariant::Aes256(key) => {
                let mut stream = aes::Aes256Ctr::from_block_cipher(key.clone(), &iv);
                stream.apply_keystream(&mut ciphertext[self.iv_size..]);
            }
        }

        Ok(ciphertext)
    }

    /// Decrypt ciphertext.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ciphertext.len() < self.iv_size {
            return Err("AesCtr: ciphertext too short".into());
        }

        let mut padded_iv = [0; AES_BLOCK_SIZE_IN_BYTES];
        padded_iv[..self.iv_size].copy_from_slice(&ciphertext[..self.iv_size]);

        let mut plaintext = Vec::with_capacity(ciphertext.len() - self.iv_size);
        plaintext.extend_from_slice(&ciphertext[self.iv_size..]);

        match &self.key {
            AesCtrVariant::Aes128(key) => {
                let mut stream = aes::Aes128Ctr::from_block_cipher(key.clone(), &padded_iv.into());
                stream.apply_keystream(&mut plaintext);
            }
            AesCtrVariant::Aes256(key) => {
                let mut stream = aes::Aes256Ctr::from_block_cipher(key.clone(), &padded_iv.into());
                stream.apply_keystream(&mut plaintext);
            }
        }
        Ok(plaintext)
    }
}
