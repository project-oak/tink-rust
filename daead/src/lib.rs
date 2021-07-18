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

//! This crate provides implementations of the [`tink_core::DeterministicAead`] primitive.
//!
//! Unlike AEAD, implementations of this interface are not semantically secure, because
//! encrypting the same plaintex always yields the same ciphertext.

#![deny(broken_intra_doc_links)]
#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use spin::{Mutex, Once};

mod aes_siv_key_manager;
pub use aes_siv_key_manager::*;
mod factory;
pub use factory::*;
mod key_templates;
pub use key_templates::*;

pub mod subtle;

/// The [upstream Tink](https://github.com/google/tink) version that this Rust
/// port is based on.
pub const UPSTREAM_VERSION: &str = "1.6.0";

static INIT: Mutex<Once> = Mutex::new(Once::new());

/// Initialize the `tink-daead` crate, registering its primitives so they are available via
/// tink-core.
pub fn init() {
    INIT.lock().call_once(|| {
        tink_core::registry::register_key_manager(Arc::new(AesSivKeyManager::default()))
            .expect("tink_daead::init() failed"); // safe: init

        tink_core::registry::register_template_generator("AES256_SIV", aes_siv_key_template);
    });
}
