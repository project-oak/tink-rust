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

//! Factory methods for [`tink_core::Verifier`] instances.

use std::sync::Arc;
use tink_core::{utils::wrap_err, TinkError};

/// Return a [`tink_core::Verifier`] primitive from the given keyset handle.
pub fn new_verifier(
    h: &tink_core::keyset::Handle,
) -> Result<Box<dyn tink_core::Verifier>, TinkError> {
    new_verifier_with_key_manager(h, None)
}

/// Return a [`tink_core::Verifier`] primitive from the given keyset handle and custom key manager.
fn new_verifier_with_key_manager(
    h: &tink_core::keyset::Handle,
    km: Option<Arc<dyn tink_core::registry::KeyManager>>,
) -> Result<Box<dyn tink_core::Verifier>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("verifier::factory: cannot obtain primitive set", e))?;

    let ret = WrappedVerifier::new(ps)?;
    Ok(Box::new(ret))
}

/// A [`tink_core::Verifier`] implementation that uses the underlying primitive set for verifying.
#[derive(Clone)]
struct WrappedVerifier {
    ps: tink_core::primitiveset::TypedPrimitiveSet<Box<dyn tink_core::Verifier>>,
}

impl WrappedVerifier {
    fn new(ps: tink_core::primitiveset::PrimitiveSet) -> Result<WrappedVerifier, TinkError> {
        let primary = match &ps.primary {
            None => return Err("verifier::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match primary.primitive {
            tink_core::Primitive::Verifier(_) => {}
            _ => return Err("verifier::factory: not a Verifier primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink_core::Primitive::Verifier(_) => {}
                    _ => return Err("verifier::factory: not a Verifier primitive".into()),
                };
            }
        }
        // The `.into()` call is only safe because we've just checked that all entries have
        // the right type of primitive
        Ok(WrappedVerifier { ps: ps.into() })
    }
}

impl tink_core::Verifier for WrappedVerifier {
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<(), TinkError> {
        let prefix_size = tink_core::cryptofmt::NON_RAW_PREFIX_SIZE;
        if signature.len() < prefix_size {
            return Err("verifier::factory: invalid signature".into());
        }

        // try non-raw keys
        let prefix = &signature[..prefix_size];
        let signature_no_prefix = &signature[prefix_size..];
        if let Some(entries) = self.ps.entries_for_prefix(prefix) {
            for entry in entries {
                let result = if entry.prefix_type == tink_proto::OutputPrefixType::Legacy {
                    let mut signed_data_copy = Vec::with_capacity(data.len() + 1);
                    signed_data_copy.extend_from_slice(data);
                    signed_data_copy.push(0u8);
                    entry
                        .primitive
                        .verify(signature_no_prefix, &signed_data_copy)
                } else {
                    entry.primitive.verify(signature_no_prefix, data)
                };
                if result.is_ok() {
                    return Ok(());
                }
            }
        }

        // try raw keys
        if let Some(entries) = self.ps.raw_entries() {
            for entry in entries {
                if entry.primitive.verify(signature, data).is_ok() {
                    return Ok(());
                }
            }
        }

        Err("verifier::factory: invalid signature".into())
    }
}
