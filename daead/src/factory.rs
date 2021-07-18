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

//! Provides an implementation of deterministic AEAD using a set of underlying implementations.

use std::sync::Arc;
use tink_core::utils::{wrap_err, TinkError};

/// Return a [`tink_core::DeterministicAead`] primitive from the given keyset handle.
pub fn new(
    h: &tink_core::keyset::Handle,
) -> Result<Box<dyn tink_core::DeterministicAead>, TinkError> {
    new_with_key_manager(h, None)
}

/// Return a [`tink_core::DeterministicAead`] primitive from the given keyset handle and custom key
/// manager.
fn new_with_key_manager(
    h: &tink_core::keyset::Handle,
    km: Option<Arc<dyn tink_core::registry::KeyManager>>,
) -> Result<Box<dyn tink_core::DeterministicAead>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("daead::factory: cannot obtain primitive set", e))?;

    let ret = WrappedDeterministicAead::new(ps)?;
    Ok(Box::new(ret))
}

/// A [`tink_core::DeterministicAead`] implementation that uses the underlying primitive set
/// for deterministic encryption and decryption.
#[derive(Clone)]
struct WrappedDeterministicAead {
    ps: tink_core::primitiveset::TypedPrimitiveSet<Box<dyn tink_core::DeterministicAead>>,
}

impl WrappedDeterministicAead {
    fn new(
        ps: tink_core::primitiveset::PrimitiveSet,
    ) -> Result<WrappedDeterministicAead, TinkError> {
        let entry = match &ps.primary {
            None => return Err("daead::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match entry.primitive {
            tink_core::Primitive::DeterministicAead(_) => {}
            _ => return Err("daead::factory: not a DeterministicAEAD primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink_core::Primitive::DeterministicAead(_) => {}
                    _ => return Err("daead::factory: not a DeterministicAEAD primitive".into()),
                };
            }
        }
        // The `.into()` call is only safe because we've just checked that all entries have
        // the right type of primitive
        Ok(WrappedDeterministicAead { ps: ps.into() })
    }
}

impl tink_core::DeterministicAead for WrappedDeterministicAead {
    fn encrypt_deterministically(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        let primary = self
            .ps
            .primary
            .as_ref()
            .ok_or_else(|| TinkError::new("no primary"))?;

        let ct = primary.primitive.encrypt_deterministically(pt, aad)?;

        let mut ret = Vec::with_capacity(primary.prefix.len() + ct.len());
        ret.extend_from_slice(&primary.prefix);
        ret.extend_from_slice(&ct);
        Ok(ret)
    }

    fn decrypt_deterministically(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        // try non-raw keys
        let prefix_size = tink_core::cryptofmt::NON_RAW_PREFIX_SIZE;
        if ct.len() > prefix_size {
            let prefix = &ct[..prefix_size];
            let ct_no_prefix = &ct[prefix_size..];
            if let Some(entries) = self.ps.entries_for_prefix(prefix) {
                for entry in entries {
                    if let Ok(pt) = entry.primitive.decrypt_deterministically(ct_no_prefix, aad) {
                        return Ok(pt);
                    }
                }
            }
        }

        // try raw keys
        if let Some(entries) = self.ps.raw_entries() {
            for entry in entries {
                if let Ok(pt) = entry.primitive.decrypt_deterministically(ct, aad) {
                    return Ok(pt);
                }
            }
        }

        // nothing worked
        Err("daead::factory: decryption failed".into())
    }
}
