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

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(broken_intra_doc_links)]

pub mod cryptofmt;
pub mod keyset;
pub mod primitiveset;
pub mod registry;
pub mod subtle;
pub mod utils;
pub use utils::TinkError;

/// The [upstream Tink](https://github.com/google/tink) version that this Rust
/// port is based on.
pub const UPSTREAM_VERSION: &str = "1.6.0";

/// Type alias for `u32` values being used as key identifiers.
pub type KeyId = u32;

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
pub enum Primitive {
    Aead(Box<dyn Aead>),
    DeterministicAead(Box<dyn DeterministicAead>),
    HybridDecrypt(Box<dyn HybridDecrypt>),
    HybridEncrypt(Box<dyn HybridEncrypt>),
    Mac(Box<dyn Mac>),
    Prf(Box<dyn Prf>),
    Signer(Box<dyn Signer>),
    StreamingAead(Box<dyn StreamingAead>),
    Verifier(Box<dyn Verifier>),
}

/// Manual implementation of the [`Clone`] trait, which makes use of the trait bounds
/// on the individual primitive types; specifically that they provide a `box_clone()`
/// method.
impl Clone for Primitive {
    fn clone(&self) -> Self {
        match self {
            Primitive::Aead(p) => Primitive::Aead(p.box_clone()),
            Primitive::DeterministicAead(p) => Primitive::DeterministicAead(p.box_clone()),
            Primitive::HybridDecrypt(p) => Primitive::HybridDecrypt(p.box_clone()),
            Primitive::HybridEncrypt(p) => Primitive::HybridEncrypt(p.box_clone()),
            Primitive::Mac(p) => Primitive::Mac(p.box_clone()),
            Primitive::Prf(p) => Primitive::Prf(p.box_clone()),
            Primitive::Signer(p) => Primitive::Signer(p.box_clone()),
            Primitive::StreamingAead(p) => Primitive::StreamingAead(p.box_clone()),
            Primitive::Verifier(p) => Primitive::Verifier(p.box_clone()),
        }
    }
}

// Conversions from the [`Primitive`] `enum` wrapper to specific primitive types.  Will panic if the
// wrong type is passed in.

impl From<Primitive> for Box<dyn Aead> {
    fn from(p: Primitive) -> Box<dyn Aead> {
        match p {
            Primitive::Aead(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}

impl From<Primitive> for Box<dyn DeterministicAead> {
    fn from(p: Primitive) -> Box<dyn DeterministicAead> {
        match p {
            Primitive::DeterministicAead(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}

impl From<Primitive> for Box<dyn HybridDecrypt> {
    fn from(p: Primitive) -> Box<dyn HybridDecrypt> {
        match p {
            Primitive::HybridDecrypt(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}

impl From<Primitive> for Box<dyn HybridEncrypt> {
    fn from(p: Primitive) -> Box<dyn HybridEncrypt> {
        match p {
            Primitive::HybridEncrypt(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}

impl From<Primitive> for Box<dyn Mac> {
    fn from(p: Primitive) -> Box<dyn Mac> {
        match p {
            Primitive::Mac(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}

impl From<Primitive> for Box<dyn Prf> {
    fn from(p: Primitive) -> Box<dyn Prf> {
        match p {
            Primitive::Prf(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}

impl From<Primitive> for Box<dyn Signer> {
    fn from(p: Primitive) -> Box<dyn Signer> {
        match p {
            Primitive::Signer(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}

impl From<Primitive> for Box<dyn StreamingAead> {
    fn from(p: Primitive) -> Box<dyn StreamingAead> {
        match p {
            Primitive::StreamingAead(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}

impl From<Primitive> for Box<dyn Verifier> {
    fn from(p: Primitive) -> Box<dyn Verifier> {
        match p {
            Primitive::Verifier(p) => p,
            _ => panic!("attempt to convert wrong primitive type"), // safe: precondition
        }
    }
}
