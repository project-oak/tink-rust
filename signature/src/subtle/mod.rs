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

//! This module provides subtle implementations of digital signature primitives.

mod ecdsa_common;
pub use ecdsa_common::*;
mod ecdsa_signer;
pub use ecdsa_signer::*;
mod ecdsa_verifier;
pub use ecdsa_verifier::*;
mod ed25519_signer;
pub use ed25519_signer::*;
mod ed25519_verifier;
pub use ed25519_verifier::*;
