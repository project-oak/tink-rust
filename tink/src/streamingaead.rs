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

//! Streaming authenticated encryption with associated data.

/// `StreamingAead` is an interface for streaming authenticated encryption with associated data.
///
/// Streaming encryption is typically used for encrypting large plaintexts such as large files.
/// Tink may eventually contain multiple interfaces for streaming encryption depending on the
/// supported properties. This interface supports a streaming interface for symmetric encryption
/// with authentication. The underlying encryption modes are selected so that partial plaintext can
/// be obtained fast by decrypting and authenticating just a part of the ciphertext.
///
/// Instances of `StreamingAead` must follow the OAE2 definition as proposed in the paper "Online
/// Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance" by [Hoang, Reyhanitabar, Rogaway
/// and Vizár](https://eprint.iacr.org/2015/189.pdf)
pub trait StreamingAead: StreamingAeadBoxClone {
    /// Return a wrapper around an underlying `std::io::Write`, such that any write-operation
    /// via the wrapper results in AEAD-encryption of the written data, using `aad`
    /// as associated authenticated data. The associated data is not included in the ciphertext
    /// and has to be passed in as parameter for decryption.
    fn new_encrypting_writer(
        &self,
        w: Box<dyn std::io::Write>,
        aad: &[u8],
    ) -> Result<Box<dyn EncryptingWrite>, crate::TinkError>;

    /// Return a wrapper around an underlying `std::io::Read`, such that any read-operation
    /// via the wrapper results in AEAD-decryption of the underlying ciphertext,
    /// using `aad` as associated authenticated data.
    fn new_decrypting_reader(
        &self,
        r: Box<dyn std::io::Read>,
        aad: &[u8],
    ) -> Result<Box<dyn std::io::Read>, crate::TinkError>;
}

/// Trait for an object that writes encrypted data.  Users must call `close()` to finish.
pub trait EncryptingWrite: std::io::Write {
    /// Close the stream, writing any final buffered data.  Any operation
    /// on the stream after this will fail.
    fn close(&mut self) -> Result<(), crate::TinkError>;
}

/// Trait bound to indicate that primitive trait objects should support cloning
/// themselves as trait objects.
pub trait StreamingAeadBoxClone {
    fn box_clone(&self) -> Box<dyn StreamingAead>;
}

/// Default implementation of the box-clone trait bound for any underlying
/// concrete type that implements [`Clone`].
impl<T> StreamingAeadBoxClone for T
where
    T: 'static + StreamingAead + Clone,
{
    fn box_clone(&self) -> Box<dyn StreamingAead> {
        Box::new(self.clone())
    }
}
