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

//! Provides an implementation of MAC using a set of underlying implementations.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::OutputPrefixType;

const MAX_INT: usize = usize::MAX >> 1;

/// Create a [`tink_core::Mac`] primitive from the given keyset handle.
pub fn new(h: &tink_core::keyset::Handle) -> Result<Box<dyn tink_core::Mac>, TinkError> {
    new_with_key_manager(h, None)
}

/// Create a [`tink_core::Mac`] primitive from the given keyset handle and a custom key manager.
fn new_with_key_manager(
    h: &tink_core::keyset::Handle,
    km: Option<Arc<dyn tink_core::registry::KeyManager>>,
) -> Result<Box<dyn tink_core::Mac>, TinkError> {
    let ps = h
        .primitives_with_key_manager(km)
        .map_err(|e| wrap_err("mac::factory: cannot obtain primitive set", e))?;

    let ret = WrappedMac::new(ps)?;
    Ok(Box::new(ret))
}

/// A [`tink_core::Mac`] implementation that uses the underlying primitive set to compute and
/// verify MACs.
#[derive(Clone)]
struct WrappedMac {
    ps: tink_core::primitiveset::TypedPrimitiveSet<Box<dyn tink_core::Mac>>,
}

impl WrappedMac {
    fn new(ps: tink_core::primitiveset::PrimitiveSet) -> Result<WrappedMac, TinkError> {
        let entry = match &ps.primary {
            None => return Err("mac::factory: no primary primitive".into()),
            Some(p) => p,
        };
        match entry.primitive {
            tink_core::Primitive::Mac(_) => {}
            _ => return Err("mac::factory: not a Mac primitive".into()),
        };
        for (_, primitives) in ps.entries.iter() {
            for p in primitives {
                match p.primitive {
                    tink_core::Primitive::Mac(_) => {}
                    _ => return Err("mac::factory: not a Mac primitive".into()),
                };
            }
        }
        // The `.into()` call is only safe because we've just checked that all entries have
        // the right type of primitive
        Ok(WrappedMac { ps: ps.into() })
    }
}

impl tink_core::Mac for WrappedMac {
    fn compute_mac(&self, data: &[u8]) -> Result<Vec<u8>, TinkError> {
        let primary = match &self.ps.primary {
            Some(p) => p,
            None => return Err("mac::factory: no primary primitive".into()),
        };
        let mac = if primary.prefix_type == OutputPrefixType::Legacy {
            if data.len() >= MAX_INT {
                return Err("mac::factory: data too long".into());
            }
            let mut local_data = Vec::with_capacity(data.len() + 1);
            local_data.extend_from_slice(data);
            local_data.push(0u8);
            primary.primitive.compute_mac(&local_data)?
        } else {
            primary.primitive.compute_mac(data)?
        };

        let mut ret = Vec::with_capacity(primary.prefix.len() + mac.len());
        ret.extend_from_slice(&primary.prefix);
        ret.extend_from_slice(&mac);
        Ok(ret)
    }

    fn verify_mac(&self, mac: &[u8], data: &[u8]) -> Result<(), TinkError> {
        // This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
        // clearly insecure, thus should be discouraged.
        let prefix_size = tink_core::cryptofmt::NON_RAW_PREFIX_SIZE;
        if mac.len() <= prefix_size {
            return Err("mac::factory: invalid mac".into());
        }

        // try non raw keys
        let prefix = &mac[..prefix_size];
        let mac_no_prefix = &mac[prefix_size..];
        if let Some(entries) = self.ps.entries_for_prefix(prefix) {
            for entry in entries {
                let result = if entry.prefix_type == OutputPrefixType::Legacy {
                    if data.len() >= MAX_INT {
                        return Err("mac::factory: data too long".into());
                    }
                    let mut local_data = Vec::with_capacity(data.len() + 1);
                    local_data.extend_from_slice(data);
                    local_data.push(0u8);
                    entry.primitive.verify_mac(mac_no_prefix, &local_data)
                } else {
                    entry.primitive.verify_mac(mac_no_prefix, data)
                };
                if result.is_ok() {
                    return Ok(());
                }
            }
        }

        if let Some(entries) = self.ps.raw_entries() {
            for entry in entries {
                let result = if entry.prefix_type == OutputPrefixType::Legacy {
                    // This diverges from the upstream Go code (as of v1.5.0), but matches the
                    // behaviour of the upstream C++/Java/Python code.
                    let mut local_data = Vec::with_capacity(data.len() + 1);
                    local_data.extend_from_slice(data);
                    local_data.push(tink_core::cryptofmt::LEGACY_START_BYTE);
                    entry.primitive.verify_mac(mac, &local_data)
                } else {
                    entry.primitive.verify_mac(mac, data)
                };
                if result.is_ok() {
                    return Ok(());
                }
            }
        }

        // nothing worked
        Err("mac::factory: decryption failed".into())
    }
}
