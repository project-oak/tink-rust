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

//! Implementations of the Signer and Verifier primitives.
//!
//! To sign data using Tink you can use ECDSA or ED25519 key templates.

#![deny(broken_intra_doc_links)]

use std::sync::Once;
use tink_core::registry::register_key_manager;

mod ecdsa_signer_key_manager;
pub use ecdsa_signer_key_manager::*;
mod ecdsa_verifier_key_manager;
pub use ecdsa_verifier_key_manager::*;
mod ed25519_signer_key_manager;
pub use ed25519_signer_key_manager::*;
mod ed25519_verifier_key_manager;
pub use ed25519_verifier_key_manager::*;
mod proto;
pub(crate) use proto::*;
mod signature_key_templates;
pub use signature_key_templates::*;
mod signer_factory;
pub use signer_factory::*;
mod verifier_factory;
pub use verifier_factory::*;

pub mod subtle;

/// The [upstream Tink](https://github.com/google/tink) version that this Rust
/// port is based on.
pub const UPSTREAM_VERSION: &str = "1.6.0";

static INIT: Once = Once::new();

/// Initialize the `tink-signature` crate, registering its primitives so they are available via
/// Tink.
pub fn init() {
    INIT.call_once(|| {
        // ECDSA
        register_key_manager(std::sync::Arc::new(EcdsaSignerKeyManager::default()))
            .expect("tink_signature::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(EcdsaVerifierKeyManager::default()))
            .expect("tink_signature::init() failed"); // safe: init

        // Ed25519
        register_key_manager(std::sync::Arc::new(Ed25519SignerKeyManager::default()))
            .expect("tink_signature::init() failed"); // safe: init
        register_key_manager(std::sync::Arc::new(Ed25519VerifierKeyManager::default()))
            .expect("tink_signature::init() failed"); // safe: init

        tink_core::registry::register_template_generator("ECDSA_P256", ecdsa_p256_key_template);
        tink_core::registry::register_template_generator(
            "ECDSA_P256_IEEE_P1363",
            ecdsa_p256_key_p1363_template,
        );
        tink_core::registry::register_template_generator("ED25519", ed25519_key_template);
        tink_core::registry::register_template_generator(
            "ED25519WithRawOutput",
            ed25519_key_without_prefix_template,
        );
    });
}
