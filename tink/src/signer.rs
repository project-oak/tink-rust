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

//! Digital signature signing.

/// `Signer` is the signing interface for digital signature.
///
/// Implementations of this trait are secure against adaptive chosen-message
/// attacks.  Signing data ensures authenticity and integrity of that data, but
/// not its secrecy.
pub trait Signer {
    // Computes the digital signature for data.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, crate::TinkError>;
}
