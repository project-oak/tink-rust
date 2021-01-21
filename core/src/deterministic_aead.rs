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

//! Deterministic authenticated encryption with associated data.

/// `DeterministicAead` is the interface for deterministic authenticated encryption with associated
/// data.
///
/// ## Warning
////
/// Unlike AEAD, implementations of this trait are not semantically secure, because
/// encrypting the same plaintex always yields the same ciphertext.
///
/// ## Security guarantees
///
/// Implementations of this trait provide 128-bit security level against multi-user attacks
/// with up to 2^32 keys. That means if an adversary obtains 2^32 ciphertexts of the same message
/// encrypted under 2^32 keys, they need to do 2^128 computations to obtain a single key.
///
/// Encryption with associated data ensures authenticity (who the sender is) and integrity (the
/// data has not been tampered with) of that data, but not its secrecy.
///
/// ## References
///
/// - [RFC 5116](https://tools.ietf.org/html/rfc5116_
/// - [RFC 5297 s1.3](https://tools.ietf.org/html/rfc5297#section-1.3)
pub trait DeterministicAead: DeterministicAeadBoxClone {
    // Deterministical encrypt plaintext with `additional_data` as additional authenticated data.
    // The resulting ciphertext allows for checking authenticity and integrity of additional
    // data `additional_data`, but there are no guarantees wrt. secrecy of that data.
    fn encrypt_deterministically(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, crate::TinkError>;

    // Deterministically decrypt ciphertext with `additional_data` as
    // additional authenticated data. The decryption verifies the authenticity and integrity
    // of the additional data, but there are no guarantees wrt. secrecy of that data.
    fn decrypt_deterministically(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, crate::TinkError>;
}

/// Trait bound to indicate that primitive trait objects should support cloning
/// themselves as trait objects.
pub trait DeterministicAeadBoxClone {
    fn box_clone(&self) -> Box<dyn DeterministicAead>;
}

/// Default implementation of the box-clone trait bound for any underlying
/// concrete type that implements [`Clone`].
impl<T> DeterministicAeadBoxClone for T
where
    T: 'static + DeterministicAead + Clone,
{
    fn box_clone(&self) -> Box<dyn DeterministicAead> {
        Box::new(self.clone())
    }
}
