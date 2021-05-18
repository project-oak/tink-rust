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

#![deny(broken_intra_doc_links)]

use std::sync::Once;
use tink_core::registry::register_key_manager;

mod aead_factory;
pub use aead_factory::*;
mod aead_key_templates;
pub use aead_key_templates::*;
mod aes_ctr_hmac_aead_key_manager;
pub use aes_ctr_hmac_aead_key_manager::*;
mod aes_gcm_key_manager;
pub use aes_gcm_key_manager::*;
mod aes_gcm_siv_key_manager;
pub use aes_gcm_siv_key_manager::*;
mod chacha20poly1305_key_manager;
pub use chacha20poly1305_key_manager::*;
mod kms_envelope_aead;
pub use kms_envelope_aead::*;
mod kms_envelope_aead_key_manager;
pub use kms_envelope_aead_key_manager::*;
mod xchacha20poly1305_key_manager;
pub use xchacha20poly1305_key_manager::*;

pub mod subtle;

/// The [upstream Tink](https://github.com/google/tink) version that this Rust
/// port is based on.
pub const UPSTREAM_VERSION: &str = "1.6.0";

static INIT: Once = Once::new();

/// Initialize the `tink-aead` crate, registering its primitives so they are available via
/// tink-core.
pub fn init() {
    INIT.call_once(|| {
        register_key_manager(std::sync::Arc::new(AesCtrHmacAeadKeyManager::default()))
            .expect("tink_aead::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(AesGcmKeyManager::default()))
            .expect("tink_aead::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(AesGcmSivKeyManager::default()))
            .expect("tink_aead::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(ChaCha20Poly1305KeyManager::default()))
            .expect("tink_aead::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(XChaCha20Poly1305KeyManager::default()))
            .expect("tink_aead::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(KmsEnvelopeAeadKeyManager::default()))
            .expect("tink_aead::init() failed"); // safe:init

        tink_core::registry::register_template_generator("AES128_GCM", aes128_gcm_key_template);
        tink_core::registry::register_template_generator("AES256_GCM", aes256_gcm_key_template);
        tink_core::registry::register_template_generator(
            "AES128_GCM_SIV",
            aes128_gcm_siv_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES256_GCM_SIV",
            aes256_gcm_siv_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES128_CTR_HMAC_SHA256",
            aes128_ctr_hmac_sha256_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES256_CTR_HMAC_SHA256",
            aes256_ctr_hmac_sha256_key_template,
        );
        tink_core::registry::register_template_generator(
            "CHACHA20_POLY1305",
            cha_cha20_poly1305_key_template,
        );
        tink_core::registry::register_template_generator(
            "XCHACHA20_POLY1305",
            x_cha_cha20_poly1305_key_template,
        );
    });
}
