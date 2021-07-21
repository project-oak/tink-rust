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

//! Digital signature verification.

use alloc::boxed::Box;

/// `Verifier` is the verifying interface for digital signature.
///
/// Implementations of this trait are secure against adaptive chosen-message
/// attacks.  Signing data ensures authenticity and integrity of that data, but
/// not its secrecy.
pub trait Verifier: VerifierBoxClone {
    /// Returns `Ok(())` if `signature` is a valid signature for `data`; otherwise returns an error.
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<(), crate::TinkError>;
}

/// Trait bound to indicate that primitive trait objects should support cloning
/// themselves as trait objects.
pub trait VerifierBoxClone {
    fn box_clone(&self) -> Box<dyn Verifier>;
}

/// Default implementation of the box-clone trait bound for any underlying
/// concrete type that implements [`Clone`].
impl<T> VerifierBoxClone for T
where
    T: 'static + Verifier + Clone,
{
    fn box_clone(&self) -> Box<dyn Verifier> {
        Box::new(self.clone())
    }
}
