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

//! This crate provides implementations of the [`tink::Mac`] primitive.
//!
//! MAC computes a tag for a given message that can be used to authenticate a
//! message.  MAC protects data integrity as well as provides for authenticity
//! of the message.

#![deny(intra_doc_link_resolution_failure)]

use std::sync::Once;

mod aes_cmac_key_manager;
pub use aes_cmac_key_manager::*;
mod factory;
pub use factory::*;
mod hmac_key_manager;
pub use hmac_key_manager::*;
mod key_templates;
pub use key_templates::*;

pub mod subtle;

static INIT: Once = Once::new();

/// Initialize the `tink-daead` crate, registering its primitives so they are available via
/// Tink.
pub fn init() {
    INIT.call_once(|| {
        tink::registry::register_key_manager(std::sync::Arc::new(HmacKeyManager::default()))
            .expect("tink_mac::init() failed");
        tink::registry::register_key_manager(std::sync::Arc::new(AesCmacKeyManager::default()))
            .expect("tink_mac::init() failed");
    });
}