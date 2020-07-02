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

//! Core crate for Tink.

#![deny(intra_doc_link_resolution_failure)]

use std::sync::Arc;

pub mod cryptofmt;
pub mod primitiveset;
pub mod proto {
    //! Auto-generated code from protocol buffer message definitions.
    include!("codegen/google.crypto.tink.rs");
}
pub mod registry;
pub mod utils;
pub use utils::TinkError;

// Traits for primitives.
mod aead;
pub use aead::*;
mod deterministic_aead;
pub use deterministic_aead::*;
mod hybrid_decrypt;
pub use hybrid_decrypt::*;
mod hybrid_encrypt;
pub use hybrid_encrypt::*;
mod mac;
pub use mac::*;
mod prf;
pub use prf::*;
mod signer;
pub use signer::*;
mod streamingaead;
pub use streamingaead::*;
mod verifier;
pub use verifier::*;

/// The primitives available in Tink.
#[derive(Clone)]
pub enum Primitive {
    Aead(Arc<dyn Aead>),
    DeterministicAead(Arc<dyn DeterministicAead>),
    HybridDecrypt(Arc<dyn HybridDecrypt>),
    HybridEncrypt(Arc<dyn HybridEncrypt>),
    Mac(Arc<dyn Mac>),
    Prf(Arc<dyn Prf>),
    Signer(Arc<dyn Signer>),
    StreamingAead(Arc<dyn StreamingAead>),
    Verifier(Arc<dyn Verifier>),
}
