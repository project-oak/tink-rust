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

//! This crate provides implementations of the [`tink::Prf`] primitive.

#![deny(intra_doc_link_resolution_failure)]

use std::sync::Once;
use tink::registry::register_key_manager;

mod aes_cmac_prf_key_manager;
pub use aes_cmac_prf_key_manager::*;
mod hkdf_prf_key_manager;
pub use hkdf_prf_key_manager::*;
mod hmac_prf_key_manager;
pub use hmac_prf_key_manager::*;
mod key_templates;
pub use key_templates::*;
mod set_factory;
pub use set_factory::*;

pub mod subtle;

static INIT: Once = Once::new();

/// Initialize the `tink-prf` crate, registering its primitives so they are available via
/// Tink.
pub fn init() {
    INIT.call_once(|| {
        register_key_manager(std::sync::Arc::new(HmacPrfKeyManager::default()))
            .expect("tink_prf::init() failed");
        register_key_manager(std::sync::Arc::new(HkdfPrfKeyManager::default()))
            .expect("tink_prf::init() failed");
        register_key_manager(std::sync::Arc::new(AesCmacPrfKeyManager::default()))
            .expect("tink_prf::init() failed");

        tink::registry::register_template_generator("HKDF_SHA256", hkdf_sha256_prf_key_template);
        tink::registry::register_template_generator(
            "HMAC_SHA256_PRF",
            hmac_sha256_prf_key_template,
        );
        tink::registry::register_template_generator(
            "HMAC_SHA512_PRF",
            hmac_sha512_prf_key_template,
        );
        tink::registry::register_template_generator("AES_CMAC_PRF", aes_cmac_prf_key_template);
    });
}
