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

//! Pseudo-random function.

/// The `Prf` trait is an abstraction for an element of a pseudo random
/// function family, selected by a key. It has the following property:
///   * It is deterministic. `compute_prf(input, length)` will always return the same output if the
///     same key is used. `compute_prf(input, length1)` will be a prefix of `compute_prf(input,
///     length2)` if `length1` < `length2` and the same key is used.
///   * It is indistinguishable from a random function: Given the evaluation of n different inputs,
///     an attacker cannot distinguish between the PRF and random bytes on an input different from
///     the n that are known.
/// Use cases for PRF are deterministic redaction of PII, keyed hash functions,
/// creating sub IDs that do not allow joining with the original dataset without
/// knowing the key.
/// While PRFs can be used in order to prove authenticity of a message, using the
/// [`Mac`](crate::Mac) interface is recommended for that use case, as it has support for
/// verification, avoiding the security problems that often happen during
/// verification, and having automatic support for key rotation. It also allows
/// for non-deterministic MAC algorithms.
pub trait Prf: PrfBoxClone {
    /// Compute the PRF selected by the underlying key on input and
    /// returns the first `output_length` bytes.
    /// When choosing this parameter keep the birthday paradox in mind.
    /// If you have 2^n different inputs that your system has to handle
    /// set the output length (in bytes) to at least
    /// ceil(n/4 + 4)
    /// This corresponds to 2*n + 32 bits, meaning a collision will occur with
    /// a probability less than 1:2^32. When in doubt, request a security review.
    /// Returns a non ok status if the algorithm fails or if the output of
    /// algorithm is less than outputLength.
    fn compute_prf(&self, input: &[u8], output_length: usize) -> Result<Vec<u8>, crate::TinkError>;
}

/// Trait bound to indicate that primitive trait objects should support cloning
/// themselves as trait objects.
pub trait PrfBoxClone {
    fn box_clone(&self) -> Box<dyn Prf>;
}

/// Default implementation of the box-clone trait bound for any underlying
/// concrete type that implements [`Clone`].
impl<T> PrfBoxClone for T
where
    T: 'static + Prf + Clone,
{
    fn box_clone(&self) -> Box<dyn Prf> {
        Box::new(self.clone())
    }
}
