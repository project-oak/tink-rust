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

//! Trait definition for key managers.

use crate::TinkError;
use alloc::string::ToString;

/// `KeyManager` "understands" keys of a specific key types: it can generate keys of a supported
/// type and create primitives for supported keys.  A key type is identified by the global name of
/// the protocol buffer that holds the corresponding key material, and is given by `type_url`-field
/// of [`KeyData`](tink_proto::KeyData)-protocol buffer.
pub trait KeyManager: Send + Sync {
    /// Construct a primitive instance for the key given in `serialized_key`, which must be a
    /// serialized key protocol buffer handled by this manager.
    fn primitive(&self, serialized_key: &[u8]) -> Result<crate::Primitive, TinkError>;

    /// Generate a new key according to specification in `serialized_key_format`, which must be
    /// supported by this manager, returned as a serialized protocol buffer.
    fn new_key(&self, serialized_key_format: &[u8]) -> Result<alloc::vec::Vec<u8>, TinkError>;

    /// Return true iff this [`KeyManager`] supports key type identified by `type_url`.
    fn does_support(&self, type_url: &str) -> bool {
        type_url == self.type_url()
    }

    /// Return the type URL that identifes the key type of keys managed by this key manager.
    fn type_url(&self) -> &'static str;

    /// Return the key material type handled by this key manager
    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType;

    // APIs for Key Management

    /// Generate a new [`KeyData`](tink_proto::KeyData) according to specification in
    /// `serialized_key_format`. This should be used solely by the key management API.
    fn new_key_data(&self, serialized_key_format: &[u8]) -> Result<tink_proto::KeyData, TinkError> {
        let serialized_key = self.new_key(serialized_key_format)?;
        Ok(tink_proto::KeyData {
            type_url: self.type_url().to_string(),
            value: serialized_key,
            key_material_type: self.key_material_type() as i32,
        })
    }

    /// Indicate whether this `KeyManager` understands private key types.
    fn supports_private_keys(&self) -> bool {
        false
    }

    /// Extract the public key data from the private key. If `supports_private_keys` returns
    /// false, this method will always return an error.
    fn public_key_data(&self, _serialized_key: &[u8]) -> Result<tink_proto::KeyData, TinkError> {
        Err("private keys not supported".into())
    }
}
