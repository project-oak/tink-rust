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

//! Trait definition for KMS clients.

/// `KmsClient` knows how to produce primitives backed by keys stored in remote KMS services.
pub trait KmsClient: Send + Sync {
    /// Returns true if this client does support `key_uri`.
    fn supported(&self, key_uri: &str) -> bool;

    /// Get an [`Aead`](crate::Aead) backend by `key_uri`.
    fn get_aead(&self, key_uri: &str) -> Result<Box<dyn crate::Aead>, crate::TinkError>;
}
