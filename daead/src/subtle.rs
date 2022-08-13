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

//! Provides subtle implementations of the `DeterministicAEAD` primitive using AES-SIV.

use aes_siv::{aead::generic_array::GenericArray, siv::Aes256Siv, KeyInit};
use std::{cell::RefCell, rc::Rc};
use tink_core::{utils::wrap_err, TinkError};

const AES_BLOCK_SIZE: usize = 16;

/// `AesSiv` is an implementation of AES-SIV-CMAC as defined in
/// [RFC 5297](https://tools.ietf.org/html/rfc5297).
///
/// `AesSiv` implements a deterministic encryption with additional data (i.e. the
/// `DeterministicAEAD` trait). Hence the implementation below is restricted
/// to one AD component.
///
/// # Security Note:
///
/// Chatterjee, Menezes and Sarkar analyze AES-SIV in Section 5.1 of
/// ["Another Look at Tightness"](https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf)
///
/// Their analysis shows that AES-SIV is susceptible to an attack in
/// a multi-user setting. Concretely, if an attacker knows the encryption
/// of a message m encrypted and authenticated with k different keys,
/// then it is possible  to find one of the MAC keys in time 2^b / k
/// where b is the size of the MAC key. A consequence of this attack
/// is that 128-bit MAC keys give unsufficient security.
/// Since 192-bit AES keys are not supported by tink for voodoo reasons
/// and RFC 5297 only supports same size encryption and MAC keys this
/// implies that keys must be 64 bytes (2*256 bits) long.
#[derive(Clone)]
pub struct AesSiv {
    // Need to use interior mutability because `aes_siv::siv::Siv` operations
    // take a `&mut self` parameter.
    cipher: Rc<RefCell<Aes256Siv>>,
}

/// Key size in bytes.
pub const AES_SIV_KEY_SIZE: usize = 64; // 512 bits

impl AesSiv {
    /// Return an [`AesSiv`] instance.
    pub fn new(key: &[u8]) -> Result<AesSiv, TinkError> {
        if key.len() != AES_SIV_KEY_SIZE {
            return Err(format!("AesSiv::new: invalid key size {}", key.len()).into());
        }

        Ok(AesSiv {
            cipher: Rc::new(RefCell::new(Aes256Siv::new(GenericArray::from_slice(key)))),
        })
    }
}

impl tink_core::DeterministicAead for AesSiv {
    fn encrypt_deterministically(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, TinkError> {
        if plaintext.len() > (isize::MAX as usize) - AES_BLOCK_SIZE {
            return Err("AesSiv: plaintext too long".into());
        }
        self.cipher
            .borrow_mut()
            .encrypt(&[additional_data], plaintext)
            .map_err(|e| wrap_err("AesSiv: encrypt failed", e))
    }

    fn decrypt_deterministically(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, TinkError> {
        if ciphertext.len() < aes_siv::siv::IV_SIZE {
            return Err("AesSiv: ciphertext is too short".into());
        }
        self.cipher
            .borrow_mut()
            .decrypt(&[additional_data], ciphertext)
            .map_err(|e| wrap_err("AesSiv: decrypt failed", e))
    }
}
