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

//! Factory methods for [`tink::StreamingAead`] instances.

use std::sync::Arc;
use tink::{utils::wrap_err, TinkError};

/// Return a [`tink::StreamingAead`] primitive from the given keyset handle.
pub fn new(h: &tink::keyset::Handle) -> Result<Box<dyn tink::StreamingAead>, TinkError> {
    new_with_key_manager(h, None)
}

/// Return a [`tink::StreamingAead`] primitive from the given keyset handle and custom key manager.
fn new_with_key_manager(
    h: &tink::keyset::Handle,
    km: Option<Arc<dyn tink::registry::KeyManager>>,
) -> Result<Box<dyn tink::StreamingAead>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("streaming_aead::factory: cannot obtain primitive set", e))?;

    let ret = WrappedStreamingAead::new(ps)?;
    Ok(Box::new(ret))
}

/// `WrappedStreamingAead` is a  [`tink::StreamingAead`] implementation that uses the underlying
/// primitive set for deterministic encryption and decryption.
#[derive(Clone)]
pub(crate) struct WrappedStreamingAead {
    pub(crate) ps: tink::primitiveset::TypedPrimitiveSet<Box<dyn tink::StreamingAead>>,
}

impl WrappedStreamingAead {
    fn new(ps: tink::primitiveset::PrimitiveSet) -> Result<WrappedStreamingAead, TinkError> {
        let entry = match &ps.primary {
            None => return Err("streaming_aead::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match entry.primitive {
            tink::Primitive::StreamingAead(_) => {}
            _ => return Err("streaming_aead::factory: not a StreamingAead primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink::Primitive::StreamingAead(_) => {}
                    _ => return Err("aead::factory: not a StreamingAead primitive".into()),
                };
            }
        }
        // The `.into()` call is only safe because we've just checked that all entries have
        // the right type of primitive
        Ok(WrappedStreamingAead { ps: ps.into() })
    }
}

impl tink::StreamingAead for WrappedStreamingAead {
    fn new_encrypting_writer(
        &self,
        w: Box<dyn std::io::Write>,
        aad: &[u8],
    ) -> Result<Box<dyn tink::EncryptingWrite>, TinkError> {
        let entry = match &self.ps.primary {
            None => return Err("streaming_aead::factory: no primary primitive".into()),
            Some(p) => p,
        };
        entry.primitive.new_encrypting_writer(w, aad)
    }

    /// Return a wrapper around an underlying `std::io::Read`, such that any read-operation
    /// via the wrapper results in AEAD-decryption of the underlying ciphertext,
    /// using `aad` as associated authenticated data.
    fn new_decrypting_reader(
        &self,
        r: Box<dyn std::io::Read>,
        aad: &[u8],
    ) -> Result<Box<dyn std::io::Read>, TinkError> {
        Ok(Box::new(crate::DecryptReader::new(self.clone(), r, aad)))
    }
}
