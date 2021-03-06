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

//! Provides a Boring-SSL backed AES-256 cipher in a form suitable for
//! use with RustCrypto traits.

use aes_siv::aead::generic_array::{
    typenum::{U16, U32, U8},
    GenericArray,
};
use std::convert::TryInto;

/// AES-256 block cipher
#[derive(Clone)]
pub struct Aes256 {
    key: [u8; 32],
}

impl cipher::NewBlockCipher for Aes256 {
    type KeySize = U32;

    #[inline]
    fn new(key: &GenericArray<u8, U32>) -> Self {
        Self {
            key: key.as_slice().try_into().unwrap(/* safe: array size checked */),
        }
    }
}

impl Aes256 {
    fn process_block(&self, block: &mut GenericArray<u8, U16>, mode: boring::symm::Mode) {
        // To process a single block, use electronic code book mode (ECB) with no padding.
        let cipher = boring::symm::Cipher::aes_256_ecb();
        let mut c = boring::symm::Crypter::new(cipher, mode, &self.key[..], None).unwrap(); // safe: size checked
        c.pad(false);
        let mut output = vec![0; block.len() + cipher.block_size()];
        // TODO(#10): investigate whether `boring` has an in-place operation.
        let count = c.update(block, &mut output).unwrap(); // safe: pure optimism
        let rest = c.finalize(&mut output[count..]).unwrap(); // safe: pure optimism
        output.truncate(count + rest);
        block[..16].copy_from_slice(&output)
    }
}

impl cipher::BlockCipher for Aes256 {
    type BlockSize = U16;
    type ParBlocks = U8;
}

impl cipher::BlockEncrypt for Aes256 {
    #[inline]
    fn encrypt_block(&self, block: &mut GenericArray<u8, U16>) {
        self.process_block(block, boring::symm::Mode::Encrypt);
    }
}

impl cipher::BlockDecrypt for Aes256 {
    #[inline]
    fn decrypt_block(&self, block: &mut GenericArray<u8, U16>) {
        self.process_block(block, boring::symm::Mode::Decrypt);
    }
}
