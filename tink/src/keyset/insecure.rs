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

//! Module for test code methods to read or write cleartext keyset material.

use crate::TinkError;

/// Create a [`Handle`](super::Handle) from cleartext key material.
fn keyset_handle(ks: tink_proto::Keyset) -> Result<super::Handle, TinkError> {
    super::Handle::from_keyset(ks)
}

/// Return the key material contained in a [`Handle`](super::Handle).
pub fn keyset_material(h: &super::Handle) -> tink_proto::Keyset {
    h.clone_keyset()
}

/// Create a new instance of [`Handle`](super::Handle) using the given
/// [`Keyset`](tink_proto::Keyset).
pub fn new_handle(ks: tink_proto::Keyset) -> Result<super::Handle, TinkError> {
    if ks.key.is_empty() {
        Err("insecure: invalid keyset".into())
    } else {
        keyset_handle(ks)
    }
}

/// Create a [`Handle`](super::Handle) from a cleartext keyset obtained via `r`.
pub fn read<T>(r: &mut T) -> Result<super::Handle, TinkError>
where
    T: super::Reader,
{
    let ks = r.read()?;
    if ks.key.is_empty() {
        Err("insecure: invalid keyset".into())
    } else {
        keyset_handle(ks)
    }
}

/// Exports the keyset from `h` to the given writer `w` without encrypting it.
/// Storing secret key material in an unencrypted fashion is dangerous. If feasible, you should use
/// [`super::Handle::write()`] instead.
pub fn write<T>(h: &super::Handle, w: &mut T) -> Result<(), TinkError>
where
    T: super::Writer,
{
    w.write(&keyset_material(h))
}
