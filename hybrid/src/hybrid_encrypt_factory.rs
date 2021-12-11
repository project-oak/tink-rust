// Copyright 2019-2021 The Tink-Rust Authors
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

//! Provides an implementation of hybrid encryption using a set of underlying implementations.

use std::sync::Arc;
use tink_core::{utils::wrap_err, TinkError};

/// Returns a [`tink_core::HybridEncrypt`] primitive from the given keyset handle.
pub fn new_encrypt(
    h: &tink_core::keyset::Handle,
) -> Result<Box<dyn tink_core::HybridEncrypt>, TinkError> {
    new_encrypt_with_key_manager(h, None)
}

/// Return a [`tink_core::HybridEncrypt`] primitive from the given keyset handle and custom key
/// manager.
fn new_encrypt_with_key_manager(
    h: &tink_core::keyset::Handle,
    km: Option<Arc<dyn tink_core::registry::KeyManager>>,
) -> Result<Box<dyn tink_core::HybridEncrypt>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("hybrid::factory: cannot obtain primitive set", e))?;

    let ret = WrappedHybridEncrypt::new(ps)?;
    Ok(Box::new(ret))
}

/// `WrappedHybridEncrypt` is a hybrid encrypt implementation that uses the underlying primitive set
/// for encryption.
#[derive(Clone)]
struct WrappedHybridEncrypt {
    ps: tink_core::primitiveset::TypedPrimitiveSet<Box<dyn tink_core::HybridEncrypt>>,
}

impl WrappedHybridEncrypt {
    fn new(ps: tink_core::primitiveset::PrimitiveSet) -> Result<WrappedHybridEncrypt, TinkError> {
        let entry = match &ps.primary {
            None => return Err("hybrid::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match entry.primitive {
            tink_core::Primitive::HybridEncrypt(_) => {}
            _ => return Err("hybrid::factory: not a HybridEncrypt primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink_core::Primitive::HybridEncrypt(_) => {}
                    _ => return Err("hybrid::factory: not a HybridEncrypt primitive".into()),
                };
            }
        }
        // The `.into()` call is only safe because we've just checked that all entries have
        // the right type of primitive
        Ok(WrappedHybridEncrypt { ps: ps.into() })
    }
}

impl tink_core::HybridEncrypt for WrappedHybridEncrypt {
    fn encrypt(&self, plaintext: &[u8], context_info: &[u8]) -> Result<Vec<u8>, TinkError> {
        let primary = self
            .ps
            .primary
            .as_ref()
            .ok_or_else(|| TinkError::new("no primary"))?;
        let p = &primary.primitive;
        let ct = p.encrypt(plaintext, context_info)?;

        let mut ret = Vec::with_capacity(primary.prefix.len() + ct.len());
        ret.extend_from_slice(&primary.prefix);
        ret.extend_from_slice(&ct);
        Ok(ret)
    }
}
