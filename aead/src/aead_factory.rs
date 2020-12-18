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

//! Provides an implementation of AEAD using a set of underlying implementations.

use tink::{utils::wrap_err, TinkError};

/// Returns a [`tink::Aead`] primitive from the given keyset handle.
pub fn new(h: &tink::keyset::Handle) -> Result<Box<dyn tink::Aead>, TinkError> {
    new_with_key_manager(h, None)
}

/// Return a [`tink::Aead`] primitive from the given keyset handle and custom key
/// manager.
pub fn new_with_key_manager(
    h: &tink::keyset::Handle,
    km: Option<std::sync::Arc<dyn tink::registry::KeyManager>>,
) -> Result<Box<dyn tink::Aead>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("aead::factory: cannot obtain primitive set", e))?;

    let ret = WrappedAead::new(ps)?;
    Ok(Box::new(ret))
}

/// `WrappedAead` is an AEAD implementation that uses the underlying primitive set for encryption
/// and decryption.
#[derive(Clone)]
struct WrappedAead {
    ps: tink::primitiveset::TypedPrimitiveSet<Box<dyn tink::Aead>>,
}

impl WrappedAead {
    fn new(ps: tink::primitiveset::PrimitiveSet) -> Result<WrappedAead, TinkError> {
        let entry = match &ps.primary {
            None => return Err("aead::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match entry.primitive {
            tink::Primitive::Aead(_) => {}
            _ => return Err("aead::factory: not an AEAD primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink::Primitive::Aead(_) => {}
                    _ => return Err("aead::factory: not an AEAD primitive".into()),
                };
            }
        }
        // The `.into()` call is only safe because we've just checked that all entries have
        // the right type of primitive
        Ok(WrappedAead { ps: ps.into() })
    }
}

impl tink::Aead for WrappedAead {
    fn encrypt(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        let primary = self
            .ps
            .primary
            .as_ref()
            .ok_or_else(|| TinkError::new("no primary"))?;

        let ct = primary.primitive.encrypt(pt, aad)?;

        let mut ret = Vec::with_capacity(primary.prefix.len() + ct.len());
        ret.extend_from_slice(&primary.prefix);
        ret.extend_from_slice(&ct);
        Ok(ret)
    }

    fn decrypt(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        // try non-raw keys
        let prefix_size = tink::cryptofmt::NON_RAW_PREFIX_SIZE;
        if ct.len() > prefix_size {
            let prefix = &ct[..prefix_size];
            let ct_no_prefix = &ct[prefix_size..];
            if let Some(entries) = self.ps.entries_for_prefix(&prefix) {
                for entry in entries {
                    if let Ok(pt) = entry.primitive.decrypt(ct_no_prefix, aad) {
                        return Ok(pt);
                    }
                }
            }
        }

        // try raw keys
        if let Some(entries) = self.ps.raw_entries() {
            for entry in entries {
                if let Ok(pt) = entry.primitive.decrypt(ct, aad) {
                    return Ok(pt);
                }
            }
        }

        // nothing worked
        Err("aead::decrypt: decryption failed".into())
    }
}
