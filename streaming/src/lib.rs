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

//! This crate provides implementations of the streaming AEAD primitive.
//!
//! AEAD encryption assures the confidentiality and authenticity of the data.
//! This primitive is CPA secure.

#![deny(broken_intra_doc_links)]

use std::sync::Once;
use tink_core::registry::register_key_manager;

mod aes_ctr_hmac_key_manager;
pub use aes_ctr_hmac_key_manager::*;
mod aes_gcm_hkdf_key_manager;
pub use aes_gcm_hkdf_key_manager::*;
mod decrypt_reader;
use decrypt_reader::*;
mod streamingaead_factory;
pub use streamingaead_factory::*;
mod streamingaead_key_templates;
pub use streamingaead_key_templates::*;

pub mod subtle;

/// The [upstream Tink](https://github.com/google/tink) version that this Rust
/// port is based on.
pub const UPSTREAM_VERSION: &str = "1.5.0";

static INIT: Once = Once::new();

pub fn init() {
    INIT.call_once(|| {
        register_key_manager(std::sync::Arc::new(AesCtrHmacKeyManager::default()))
            .expect("tink_streaming_aead::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(AesGcmHkdfKeyManager::default()))
            .expect("tink_streaming_aead::init() failed"); // safe: init

        tink_core::registry::register_template_generator(
            "AES128_CTR_HMAC_SHA256_4KB",
            aes128_gcm_hkdf_4kb_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES128_CTR_HMAC_SHA256_1MB",
            aes128_gcm_hkdf_1mb_key_template,
        );

        tink_core::registry::register_template_generator(
            "AES256_CTR_HMAC_SHA256_4KB",
            aes256_gcm_hkdf_4kb_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES256_CTR_HMAC_SHA256_1MB",
            aes256_gcm_hkdf_1mb_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES128_GCM_HKDF_4KB",
            aes128_ctr_hmac_sha256_segment_4kb_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES128_GCM_HKDF_1MB",
            aes128_ctr_hmac_sha256_segment_1mb_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES256_GCM_HKDF_4KB",
            aes256_ctr_hmac_sha256_segment_4kb_key_template,
        );
        tink_core::registry::register_template_generator(
            "AES256_GCM_HKDF_1MB",
            aes256_ctr_hmac_sha256_segment_1mb_key_template,
        );
    });
}
