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

//! Provides an implementation of hybrid decryption using a set of underlying implementations.

use std::sync::Arc;
use tink_core::{utils::wrap_err, TinkError};

/// Returns a [`tink_core::HybridDecrypt`] primitive from the given keyset handle.
pub fn new_decrypt(
    h: &tink_core::keyset::Handle,
) -> Result<Box<dyn tink_core::HybridDecrypt>, TinkError> {
    new_decrypt_with_key_manager(h, None)
}

/// Return a [`tink_core::HybridDecrypt`] primitive from the given keyset handle and custom key
/// manager.
fn new_decrypt_with_key_manager(
    h: &tink_core::keyset::Handle,
    km: Option<Arc<dyn tink_core::registry::KeyManager>>,
) -> Result<Box<dyn tink_core::HybridDecrypt>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("hybrid::factory: cannot obtain primitive set", e))?;

    let ret = WrappedHybridDecrypt::new(ps)?;
    Ok(Box::new(ret))
}

/// `WrappedHybridDecrypt` is a hybrid decrypt implementation that uses the underlying primitive set
/// for decryption.
#[derive(Clone)]
struct WrappedHybridDecrypt {
    ps: tink_core::primitiveset::TypedPrimitiveSet<Box<dyn tink_core::HybridDecrypt>>,
}

impl WrappedHybridDecrypt {
    fn new(ps: tink_core::primitiveset::PrimitiveSet) -> Result<WrappedHybridDecrypt, TinkError> {
        let entry = match &ps.primary {
            None => return Err("hybrid::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match entry.primitive {
            tink_core::Primitive::HybridDecrypt(_) => {}
            _ => return Err("hybrid::factory: not a HybridDecrypt primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink_core::Primitive::HybridDecrypt(_) => {}
                    _ => return Err("hybrid::factory: not a HybridDecrypt primitive".into()),
                };
            }
        }
        // The `.into()` call is only safe because we've just checked that all entries have
        // the right type of primitive
        Ok(WrappedHybridDecrypt { ps: ps.into() })
    }
}

impl tink_core::HybridDecrypt for WrappedHybridDecrypt {
    fn decrypt(&self, ciphertext: &[u8], context_info: &[u8]) -> Result<Vec<u8>, TinkError> {
        // try non-raw keys
        let prefix_size = tink_core::cryptofmt::NON_RAW_PREFIX_SIZE;
        if ciphertext.len() > prefix_size {
            let prefix = &ciphertext[..prefix_size];
            let ct_no_prefix = &ciphertext[prefix_size..];
            if let Some(entries) = self.ps.entries_for_prefix(prefix) {
                for entry in entries {
                    let result = entry.primitive.decrypt(ct_no_prefix, context_info);
                    if result.is_ok() {
                        return result;
                    }
                }
            }
        }

        // try raw keys
        if let Some(entries) = self.ps.raw_entries() {
            for entry in entries {
                let result = entry.primitive.decrypt(ciphertext, context_info);
                if result.is_ok() {
                    return result;
                }
            }
        }

        Err("hybrid::factory: decryption failed".into())
    }
}
