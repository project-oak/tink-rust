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

//! Utilities for managing keys in a keyset.

use crate::{
    proto::{KeyStatusType, OutputPrefixType},
    utils::wrap_err,
    KeyId, TinkError,
};
use rand::Rng;

/// Manager manages a [`Keyset`](crate::proto::Keyset)-proto, with convenience methods that rotate,
/// disable, enable or destroy keys. Note: It is not thread-safe.
#[derive(Default)]
pub struct Manager {
    ks: crate::proto::Keyset,
}

impl Manager {
    /// Create a new instance with an empty [`Keyset`](crate::proto::Keyset).
    pub fn new() -> Self {
        Self {
            ks: crate::proto::Keyset::default(),
        }
    }

    /// Create a new instance from the given [`Handle`](super::Handle).
    pub fn new_from_handle(kh: super::Handle) -> Self {
        Self {
            ks: kh.into_inner(),
        }
    }

    /// Generate a fresh key using the given key template and set the new key as the primary key.
    /// The key that was primary prior to rotation remains `Enabled`. Returns the key ID of the
    /// new primary key.
    pub fn rotate(&mut self, kt: &crate::proto::KeyTemplate) -> Result<KeyId, TinkError> {
        self.add(kt, true)
    }

    /// Generate a fresh key using the given key template, and optionally set the new key as the
    /// primary key. Returns the key ID of the added key.
    pub fn add(
        &mut self,
        kt: &crate::proto::KeyTemplate,
        as_primary: bool,
    ) -> Result<KeyId, TinkError> {
        let key_data = crate::registry::new_key_data(kt)
            .map_err(|e| wrap_err("keyset::Manager: cannot create KeyData", e))?;
        let key_id = self.new_key_id();
        let mut output_prefix_type = kt.output_prefix_type;
        if OutputPrefixType::from_i32(output_prefix_type) == Some(OutputPrefixType::UnknownPrefix) {
            output_prefix_type = OutputPrefixType::Tink as i32;
        }
        let key = crate::proto::keyset::Key {
            key_data: Some(key_data),
            status: crate::proto::KeyStatusType::Enabled as i32,
            key_id,
            output_prefix_type,
        };
        self.ks.key.push(key);
        if as_primary {
            // Set the new key as the primary key
            self.ks.primary_key_id = key_id;
        }
        Ok(key_id)
    }

    /// Create a new [`Handle`](super::Handle) for the managed keyset.
    pub fn handle(&self) -> Result<super::Handle, TinkError> {
        Ok(super::Handle::from_keyset(self.ks.clone()))
    }

    /// Sets the status of the specified key to [`KeyStatusType::Enabled`].  Succeeds only if before
    /// the call the specified key has status [`KeyStatusType::Disabled`] or
    /// [`KeyStatusType::Enabled`].
    pub fn enable(&mut self, key_id: KeyId) -> Result<(), TinkError> {
        for key in &mut self.ks.key {
            if key.key_id == key_id {
                return match KeyStatusType::from_i32(key.status) {
                    Some(KeyStatusType::Enabled) | Some(KeyStatusType::Disabled) => {
                        key.status = KeyStatusType::Enabled as i32;
                        Ok(())
                    }
                    _ => Err(format!(
                        "Cannot enable key with key_id {} and status {}",
                        key_id, key.status
                    )
                    .into()),
                };
            }
        }
        Err(format!("Key {} not found", key_id).into())
    }

    /// Sets the status of the specified key to [`KeyStatusType::Disabled`].
    /// Succeeds only if before the call the specified key
    /// is not primary and has status [`KeyStatusType::Disabled`] or [`KeyStatusType::Enabled`].
    pub fn disable(&mut self, key_id: KeyId) -> Result<(), TinkError> {
        if self.ks.primary_key_id == key_id {
            return Err(format!("Cannot disable primary key (key_id {})", key_id).into());
        }
        for key in &mut self.ks.key {
            if key.key_id == key_id {
                return match KeyStatusType::from_i32(key.status) {
                    Some(KeyStatusType::Enabled) | Some(KeyStatusType::Disabled) => {
                        key.status = KeyStatusType::Disabled as i32;
                        Ok(())
                    }
                    _ => Err(format!(
                        "Cannot disable key with key_id {} and status {}",
                        key_id, key.status
                    )
                    .into()),
                };
            }
        }
        Err(format!("Key {} not found", key_id).into())
    }

    /// Sets the status of the specified key to [`KeyStatusType::Destroyed`], and removes the
    /// corresponding key material, if any.  Succeeds only if before the call the specified key
    /// is not primary and has status [`KeyStatusType::Disabled`], or
    /// [`KeyStatusType::Enabled`], or [`KeyStatusType::Destroyed`].
    pub fn destroy(&mut self, key_id: KeyId) -> Result<(), TinkError> {
        if self.ks.primary_key_id == key_id {
            return Err(format!("Cannot destroy primary key (key_id {})", key_id).into());
        }
        for key in &mut self.ks.key {
            if key.key_id == key_id {
                return match KeyStatusType::from_i32(key.status) {
                    Some(KeyStatusType::Enabled)
                    | Some(KeyStatusType::Disabled)
                    | Some(KeyStatusType::Destroyed) => {
                        key.key_data = None;
                        key.status = KeyStatusType::Destroyed as i32;
                        Ok(())
                    }
                    _ => Err(format!(
                        "Cannot destroy key with key_id {} and status {}",
                        key_id, key.status
                    )
                    .into()),
                };
            }
        }
        Err(format!("Key {} not found", key_id).into())
    }

    /// Removes the specifed key from the managed keyset.  Succeeds only if the specified key is not
    /// primary.  After deletion the keyset contains one key fewer.
    pub fn delete(&mut self, key_id: KeyId) -> Result<(), TinkError> {
        if self.ks.primary_key_id == key_id {
            return Err(format!("Cannot delete primary key (key_id {})", key_id).into());
        }
        let mut idx: Option<usize> = None;
        for (i, key) in self.ks.key.iter().enumerate() {
            if key.key_id == key_id {
                idx = Some(i);
                break;
            }
        }
        match idx {
            Some(i) => {
                self.ks.key.remove(i);
                Ok(())
            }
            None => Err(format!("Key {} not found", key_id).into()),
        }
    }

    /// Sets the specified key as the primary.  Succeeds only if the specified key is `Enabled`.
    pub fn set_primary(&mut self, key_id: KeyId) -> Result<(), TinkError> {
        for key in &self.ks.key {
            if key.key_id == key_id {
                return match KeyStatusType::from_i32(key.status) {
                    Some(KeyStatusType::Enabled) => {
                        self.ks.primary_key_id = key_id;
                        Ok(())
                    }
                    _ => Err(format!(
                        "The candidate (key_id {}) for the primary key must be Enabled (status {})",
                        key_id, key.status
                    )
                    .into()),
                };
            }
        }
        Err(format!("Key {} not found", key_id).into())
    }

    /// Return the count of all keys in the keyset.
    pub fn key_count(&self) -> usize {
        self.ks.key.len()
    }

    /// Generate a key id that has not been used by any key in the [`Keyset`](crate::proto::Keyset).
    fn new_key_id(&self) -> KeyId {
        let mut rng = rand::thread_rng();

        loop {
            let ret = rng.gen::<u32>();
            if self.ks.key.iter().any(|x| x.key_id == ret) {
                continue;
            }
            return ret;
        }
    }
}
