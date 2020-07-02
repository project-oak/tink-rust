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

use crate::{proto::OutputPrefixType, utils::wrap_err, TinkError};
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
        Self { ks: kh.ks }
    }

    /// Generate a fresh key using the given key template and
    /// sets the new key as the primary key.
    pub fn rotate(&mut self, kt: &crate::proto::KeyTemplate) -> Result<(), TinkError> {
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
        // Set the new key as the primary key
        self.ks.key.push(key);
        self.ks.primary_key_id = key_id;
        Ok(())
    }

    /// Create a new [`Handle`](super::Handle) for the managed keyset.
    pub fn handle(&self) -> Result<super::Handle, TinkError> {
        Ok(super::Handle {
            ks: self.ks.clone(),
        })
    }

    /// Generate a key id that has not been used by any key in the [`Keyset`](crate::proto::Keyset).
    fn new_key_id(&self) -> u32 {
        let mut rng = rand::thread_rng();

        loop {
            let ret = rng.gen::<u32>();
            let mut ok = true;
            for key in &self.ks.key {
                if key.key_id == ret {
                    ok = false;
                    break;
                }
            }
            if ok {
                return ret;
            }
        }
    }
}
