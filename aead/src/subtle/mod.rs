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

//! Provides subtle implementations of the `tink_core::Aead` primitive.

mod aead;
pub use self::aead::*;
mod aes_ctr;
pub use self::aes_ctr::*;
mod aes_gcm;
pub use self::aes_gcm::*;
mod aes_gcm_siv;
pub use self::aes_gcm_siv::*;
mod chacha20poly1305;
pub use self::chacha20poly1305::*;
mod encrypt_then_authenticate;
pub use encrypt_then_authenticate::*;
mod ind_cpa;
pub use ind_cpa::*;
mod xchacha20poly1305;
pub use self::xchacha20poly1305::*;
