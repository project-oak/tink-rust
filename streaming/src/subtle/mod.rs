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

//! Provides subtle implementations of the Streaming AEAD primitive.

mod aes_ctr_hmac;
pub use aes_ctr_hmac::*;
mod aes_gcm_hkdf;
pub use aes_gcm_hkdf::*;

pub mod noncebased;

/// Check if the given key size is a valid AES key size.
/// (This is a copy of the function in tink_aead::subtle, to reduce inter-crate deps.)
pub fn validate_aes_key_size(size_in_bytes: usize) -> Result<(), tink::TinkError> {
    match size_in_bytes {
        16 | 32 => Ok(()),
        _ => Err(format!("invalid AES key size; want 16 or 32, got {}", size_in_bytes).into()),
    }
}
