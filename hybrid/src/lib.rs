// Copyright 2019-2021 The Tink-Rust Authors
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

//! Implementations of the `HybridEncrypt` and `HybridDecrypt` primitives.
//!
//! The functionality of Hybrid Encryption is represented as a pair of primitives (interfaces):
//!
//! - HybridEncrypt for encryption of data
//! - HybridDecrypt for decryption of data
//!
//! Implementations of these interfaces are secure against adaptive chosen ciphertext attacks. In
//! addition to plaintext the encryption takes an extra parameter contextInfo, which usually is
//! public data implicit from the context, but should be bound to the resulting ciphertext, i.e. the
//! ciphertext allows for checking the integrity of `context_info` (but there are no guarantees wrt.
//! the secrecy or authenticity of `context_info`).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]

use std::sync::Once;
use tink_core::registry::{register_key_manager, register_template_generator};

mod ecies_aead_hkdf_dem_helper;
pub use ecies_aead_hkdf_dem_helper::*;
mod ecies_aead_hkdf_private_key_manager;
pub use ecies_aead_hkdf_private_key_manager::*;
mod ecies_aead_hkdf_public_key_manager;
pub use ecies_aead_hkdf_public_key_manager::*;
mod hybrid_decrypt_factory;
pub use hybrid_decrypt_factory::*;
mod hybrid_encrypt_factory;
pub use hybrid_encrypt_factory::*;
mod hybrid_key_templates;
pub use hybrid_key_templates::*;

pub mod subtle;

/// The [upstream Tink](https://github.com/google/tink) version that this Rust
/// port is based on.
pub const UPSTREAM_VERSION: &str = "1.6.0";

static INIT: Once = Once::new();

/// Initialize the `tink-hybrid` crate, registering its primitives so they are available via
/// Tink.
pub fn init() {
    #[cfg(feature = "aead")]
    tink_aead::init();
    #[cfg(feature = "daead")]
    tink_daead::init();
    INIT.call_once(|| {
        register_key_manager(std::sync::Arc::new(
            EciesAeadHkdfPrivateKeyKeyManager::default(),
        ))
        .expect("tink_hybrid::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(
            EciesAeadHkdfPublicKeyKeyManager::default(),
        ))
        .expect("tink_hybrid::init() failed"); // safe: init

        register_template_generator(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
            ecies_hkdf_aes128_gcm_key_template,
        );
        register_template_generator(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            ecies_hkdf_aes128_ctr_hmac_sha256_key_template,
        );
    });
}
