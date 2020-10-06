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

//! Factory methods for [`tink::Verifier`] instances.

use std::sync::Arc;
use tink::{utils::wrap_err, TinkError};

/// Return a [`tink::Verifier`] primitive from the given keyset handle.
pub fn new_verifier(h: &tink::keyset::Handle) -> Result<Box<dyn tink::Verifier>, TinkError> {
    new_verifier_with_key_manager(h, None)
}

/// Return a [`tink::Verifier`] primitive from the given keyset handle and custom key manager.
pub fn new_verifier_with_key_manager(
    h: &tink::keyset::Handle,
    km: Option<Arc<dyn tink::registry::KeyManager>>,
) -> Result<Box<dyn tink::Verifier>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("verifier::factory: cannot obtain primitive set", e))?;

    let ret = WrappedVerifier::new(ps)?;
    Ok(Box::new(ret))
}

/// A [`tink::Verifier`] implementation that uses the underlying primitive set for verifying.
struct WrappedVerifier {
    ps: tink::primitiveset::PrimitiveSet,
}

impl WrappedVerifier {
    fn new(ps: tink::primitiveset::PrimitiveSet) -> Result<WrappedVerifier, TinkError> {
        let primary = match &ps.primary {
            None => return Err("verifier::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match primary.primitive {
            tink::Primitive::Verifier(_) => {}
            _ => return Err("verifier::factory: not a Verifier primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink::Primitive::Verifier(_) => {}
                    _ => return Err("verifier::factory: not a Verifier primitive".into()),
                };
            }
        }
        Ok(WrappedVerifier { ps })
    }
}

impl tink::Verifier for WrappedVerifier {
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<(), TinkError> {
        let prefix_size = tink::cryptofmt::NON_RAW_PREFIX_SIZE;
        if signature.len() < prefix_size {
            return Err("verifier::factory: invalid signature".into());
        }

        // try non-raw keys
        let prefix = &signature[..prefix_size];
        let signature_no_prefix = &signature[prefix_size..];
        let entries = self.ps.entries_for_prefix(&prefix);
        for entry in &entries {
            if let tink::Primitive::Verifier(p) = &entry.primitive {
                let result = if entry.prefix_type == tink::proto::OutputPrefixType::Legacy {
                    let mut signed_data_copy = Vec::with_capacity(data.len() + 1);
                    signed_data_copy.extend_from_slice(data);
                    signed_data_copy.push(tink::cryptofmt::LEGACY_START_BYTE);
                    p.verify(signature_no_prefix, &signed_data_copy)
                } else {
                    p.verify(signature_no_prefix, data)
                };
                if result.is_ok() {
                    return Ok(());
                }
            } else {
                return Err("verifier::factory: not a Verifier primitive".into());
            }
        }

        // try raw keys
        let entries = self.ps.raw_entries();
        for entry in &entries {
            if let tink::Primitive::Verifier(p) = &entry.primitive {
                if p.verify(signature, data).is_ok() {
                    return Ok(());
                }
            } else {
                return Err("verifier::factory: not a Verifier primitive".into());
            }
        }

        Err("verifier::factory: invalid signature".into())
    }
}
