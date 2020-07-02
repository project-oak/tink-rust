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
use tink::utils::{wrap_err, TinkError};

/// Return a [`tink::DeterministicAead`] primitive from the given keyset handle.
pub fn new(h: &tink::keyset::Handle) -> Result<Box<dyn tink::DeterministicAead>, TinkError> {
    new_with_key_manager(h, None)
}

/// Return a [`tink::DeterministicAead`] primitive from the given keyset handle and custom key
/// manager.
pub fn new_with_key_manager(
    h: &tink::keyset::Handle,
    km: Option<Arc<dyn tink::registry::KeyManager>>,
) -> Result<Box<dyn tink::DeterministicAead>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("daead::factory: cannot obtain primitive set", e))?;
    if let Some(primary) = &ps.primary {
        match primary.primitive {
            tink::Primitive::DeterministicAead(_) => {}
            _ => return Err("daead::factory: not a DeterministicAEAD primitive".into()),
        }
    } else {
        return Err("deaed::factory: no primary primitive".into());
    }
    for (_, primitives) in ps.entries.iter() {
        for p in primitives {
            match p.primitive {
                tink::Primitive::DeterministicAead(_) => {}
                _ => return Err("daead::factory: not a DeterministicAEAD primitive".into()),
            };
        }
    }
    let ret = WrappedDeterministicAead { ps };
    Ok(Box::new(ret))
}

// A [`tink::DeterministicAead`] implementation that uses the underlying primitive set
// for deterministic encryption and decryption.
struct WrappedDeterministicAead {
    ps: tink::primitiveset::PrimitiveSet,
}

impl tink::DeterministicAead for WrappedDeterministicAead {
    fn encrypt_deterministically(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        let primary = self
            .ps
            .primary
            .as_ref()
            .ok_or_else(|| TinkError::new("no primary"))?;

        match &primary.primitive {
            tink::Primitive::DeterministicAead(p) => {
                let ct = p.encrypt_deterministically(pt, aad)?;

                let mut ret = Vec::with_capacity(primary.prefix.len() + ct.len());
                ret.extend_from_slice(&primary.prefix);
                ret.extend_from_slice(&ct);
                Ok(ret)
            }
            _ => Err("daead::factory: not a DeterministicAEAD primitive".into()),
        }
    }

    fn decrypt_deterministically(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        // try non-raw keys
        let prefix_size = tink::cryptofmt::NON_RAW_PREFIX_SIZE;
        if ct.len() > prefix_size {
            let prefix = &ct[..prefix_size];
            let ct_no_prefix = &ct[prefix_size..];
            let entries = self.ps.entries_for_prefix(&prefix);
            for entry in &entries {
                if let tink::Primitive::DeterministicAead(p) = &entry.primitive {
                    if let Ok(pt) = p.decrypt_deterministically(ct_no_prefix, aad) {
                        return Ok(pt);
                    }
                } else {
                    return Err("daead::factory: not a DeterministicAEAD primitive".into());
                }
            }
        }

        // try raw keys
        let entries = self.ps.raw_entries();
        for entry in &entries {
            if let tink::Primitive::DeterministicAead(p) = &entry.primitive {
                if let Ok(pt) = p.decrypt_deterministically(ct, aad) {
                    return Ok(pt);
                }
            } else {
                return Err("daead::factory: not a DeterministicAEAD primitive".into());
            }
        }

        // nothing worked
        Err("daead::factory: decryption failed".into())
    }
}
