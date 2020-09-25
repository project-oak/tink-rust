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

//! Trait definition for `IndCpaCipher`.

// `IndCpaCipher` provides an interface for symmetric key ciphers that are
// indistinguishable against chosen-plaintext attacks. Said primitives do not
// provide authentication, thus should not be used directly, but only to
// construct safer primitives such as AEAD.
pub trait IndCpaCipher {
    // Encrypt plaintext. The resulting ciphertext is indistinguishable under
    // chosen-plaintext attack. However, it does not have integrity protection.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, tink::TinkError>;

    // Decrypt ciphertext and returns the resulting plaintext.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, tink::TinkError>;
}
