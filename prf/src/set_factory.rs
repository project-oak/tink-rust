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

//! Provides an implementation of PRF using a set of underlying implementations.

use std::{collections::HashMap, sync::Arc};
use tink::{utils::wrap_err, Prf, TinkError};

/// `Set` is a set of PRFs. A [`Keyset`](tink_proto::Keyset) can be converted into a set of PRFs
/// using this primitive. Every key in the keyset corresponds to a PRF in the prf.Set.
/// Every PRF in the set is given an ID, which is the same ID as the key id in
/// the `Keyset`.
pub struct Set {
    /// The key ID marked as primary in the corresponding [`Keyset`](tink_proto::Keyset).
    pub primary_id: u32,
    /// Map key IDs to their corresponding Prf.
    pub prfs: HashMap<u32, Box<dyn Prf>>,
}

impl Set {
    /// Create a [`Set`] from the given keyset handle.
    pub fn new(h: &tink::keyset::Handle) -> Result<Set, TinkError> {
        Set::new_with_key_manager(h, None)
    }

    /// Creates a [`Set`] primitive from the given keyset handle and a custom key manager.
    fn new_with_key_manager(
        h: &tink::keyset::Handle,
        km: Option<Arc<dyn tink::registry::KeyManager>>,
    ) -> Result<Set, TinkError> {
        let ps = h
            .primitives_with_key_manager(km)
            .map_err(|e| wrap_err("prf::Set: cannot obtain primitive set", e))?;
        wrap_prf_set(ps)
    }

    /// Equivalent to `self.prfs[set.primary_id].compute_prf(input, output_length)`.
    pub fn compute_primary_prf(
        &self,
        input: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, TinkError> {
        let prf = self.prfs.get(&self.primary_id).ok_or_else(|| {
            TinkError::new(&format!(
                "Could not find primary ID {} in prf.Set",
                self.primary_id
            ))
        })?;
        prf.compute_prf(input, output_length)
    }
}

fn wrap_prf_set(ps: tink::primitiveset::PrimitiveSet) -> Result<Set, TinkError> {
    let entry = match &ps.primary {
        None => return Err("prf::Set: no primary available".into()),
        Some(e) => e,
    };
    match entry.primitive {
        tink::Primitive::Prf(_) => {}
        _ => return Err("prf::Set: not a PRF primitive".into()),
    }
    let mut set = Set {
        primary_id: entry.key_id,
        prfs: HashMap::new(),
    };

    let entries = ps.raw_entries();
    if entries.is_empty() {
        return Err("Did not find any raw entries".into());
    }
    if ps.entries.len() != 1 {
        return Err("Only raw entries allowed for prf::Set".into());
    }
    for entry in entries {
        let prf = match entry.primitive {
            tink::Primitive::Prf(prf) => prf,
            _ => return Err("prf::Set: not a PRF primitive".into()),
        };
        set.prfs.insert(entry.key_id, prf);
    }

    Ok(set)
}
