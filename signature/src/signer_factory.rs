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

//! Factory methods for [`tink::Signer`] instances.

use std::sync::Arc;
use tink::{utils::wrap_err, TinkError};

/// Return a [`tink::Signer`] primitive from the given keyset handle.
pub fn new_signer(h: &tink::keyset::Handle) -> Result<Box<dyn tink::Signer>, TinkError> {
    new_signer_with_key_manager(h, None)
}

/// Return a [`tink::Signer`] primitive from the given keyset handle and custom key manager.
pub fn new_signer_with_key_manager(
    h: &tink::keyset::Handle,
    km: Option<Arc<dyn tink::registry::KeyManager>>,
) -> Result<Box<dyn tink::Signer>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("signer::factory: cannot obtain primitive set", e))?;

    let ret = WrappedSigner::new(ps)?;
    Ok(Box::new(ret))
}

/// A [`tink::Signer`] implementation that uses the underlying primitive set for signing.
struct WrappedSigner {
    ps: tink::primitiveset::PrimitiveSet,
}

impl WrappedSigner {
    fn new(ps: tink::primitiveset::PrimitiveSet) -> Result<WrappedSigner, TinkError> {
        let primary = match &ps.primary {
            None => return Err("signer::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match primary.primitive {
            tink::Primitive::Signer(_) => {}
            _ => return Err("signer::factory: not a Signer primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink::Primitive::Signer(_) => {}
                    _ => return Err("signer::factory: not a Signer primitive".into()),
                };
            }
        }
        Ok(WrappedSigner { ps })
    }
}

impl tink::Signer for WrappedSigner {
    /// Sign the given data and returns the signature concatenated with the identifier of the
    /// primary primitive.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TinkError> {
        let primary = match &self.ps.primary {
            Some(p) => p,
            None => return Err("signer::factory: no primary primitive".into()),
        };
        let primitive = match &primary.primitive {
            tink::Primitive::Signer(p) => p,
            _ => return Err("signer::factory: not a Mac primitive".into()),
        };

        let signature = if primary.prefix_type == tink::proto::OutputPrefixType::Legacy {
            let mut signed_data_copy = Vec::with_capacity(data.len() + 1);
            signed_data_copy.extend_from_slice(data);
            signed_data_copy.push(tink::cryptofmt::LEGACY_START_BYTE);
            primitive.sign(&signed_data_copy)?
        } else {
            primitive.sign(data)?
        };

        let mut ret = Vec::with_capacity(primary.prefix.len() + signature.len());
        ret.extend_from_slice(&primary.prefix);
        ret.extend_from_slice(&signature);
        Ok(ret)
    }
}
