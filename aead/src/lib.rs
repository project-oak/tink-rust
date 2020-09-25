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

//! Provides implementations of the AEAD primitive.
//!
//! AEAD encryption assures the confidentiality and authenticity of the data. This primitive is CPA
//! secure.

#![deny(intra_doc_link_resolution_failure)]

use std::sync::Once;
use tink::registry::register_key_manager;

mod aead_factory;
pub use aead_factory::*;
mod aead_key_templates;
pub use aead_key_templates::*;
mod aes_ctr_hmac_aead_key_manager;
pub use aes_ctr_hmac_aead_key_manager::*;
mod aes_gcm_key_manager;
pub use aes_gcm_key_manager::*;
mod chacha20poly1305_key_manager;
pub use chacha20poly1305_key_manager::*;
mod kms_envelope_aead;
pub use kms_envelope_aead::*;
mod kms_envelope_aead_key_manager;
pub use kms_envelope_aead_key_manager::*;
mod xchacha20poly1305_key_manager;
pub use xchacha20poly1305_key_manager::*;

pub mod subtle;

static INIT: Once = Once::new();

/// Initialize the `tink-aead` crate, registering its primitives so they are available via
/// tink.
pub fn init() {
    INIT.call_once(|| {
        register_key_manager(std::sync::Arc::new(AesCtrHmacAeadKeyManager::default()))
            .expect("tink_aead::init() failed");
        register_key_manager(std::sync::Arc::new(AesGcmKeyManager::default()))
            .expect("tink_aead::init() failed");
        register_key_manager(std::sync::Arc::new(ChaCha20Poly1305KeyManager::default()))
            .expect("tink_aead::init() failed");
        register_key_manager(std::sync::Arc::new(XChaCha20Poly1305KeyManager::default()))
            .expect("tink_aead::init() failed");
        register_key_manager(std::sync::Arc::new(KmsEnvelopeAeadKeyManager::default()))
            .expect("tink_aead::init() failed");
    });
}
