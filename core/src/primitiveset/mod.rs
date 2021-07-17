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

//! Provides a container for a set of cryptographic primitives.
//!
//! It provides also additional properties for the primitives it holds. In
//! particular, one of the primitives in the set can be distinguished as "the
//! primary" one.

use crate::utils::{wrap_err, TinkError};
use alloc::{
    boxed::Box,
    collections::{btree_map, BTreeMap},
    vec,
    vec::Vec,
};

/// `Entry` represents a single entry in the keyset. In addition to the actual
/// primitive, it holds the identifier and status of the primitive.
#[derive(Clone)]
pub struct Entry {
    pub key_id: crate::KeyId,
    pub primitive: crate::Primitive,
    pub prefix: Vec<u8>,
    pub prefix_type: tink_proto::OutputPrefixType,
    pub status: tink_proto::KeyStatusType,
}

impl Entry {
    fn new(
        key_id: crate::KeyId,
        p: crate::Primitive,
        prefix: &[u8],
        prefix_type: tink_proto::OutputPrefixType,
        status: tink_proto::KeyStatusType,
    ) -> Self {
        Entry {
            key_id,
            primitive: p,
            prefix: prefix.to_vec(),
            prefix_type,
            status,
        }
    }
}

/// `PrimitiveSet` is used for supporting key rotation: primitives in a set
/// correspond to keys in a keyset. Users will usually work with primitive
/// instances, which essentially wrap primitive sets. For example an instance of
/// an AEAD-primitive for a given keyset holds a set of AEAD-primitives
/// corresponding to the keys in the keyset, and uses the set members to do the
/// actual crypto operations: to encrypt data the primary AEAD-primitive from
/// the set is used, and upon decryption the ciphertext's prefix determines the
/// id of the primitive from the set.
///
/// `PrimitiveSet` is public to allow its use in implementations of custom
/// primitives.
#[derive(Clone, Default)]
pub struct PrimitiveSet {
    // Copy of the primary entry in `entries`.
    pub primary: Option<Entry>,

    // The primitives are stored in a map of (ciphertext prefix, list of
    // primitives sharing the prefix). This allows quickly retrieving the
    // primitives sharing some particular prefix.
    pub entries: BTreeMap<Vec<u8>, Vec<Entry>>,
}

impl PrimitiveSet {
    /// Return an empty instance of [`PrimitiveSet`].
    pub fn new() -> Self {
        PrimitiveSet {
            primary: None,
            entries: BTreeMap::new(),
        }
    }

    /// Return all primitives in the set that have RAW prefix.
    pub fn raw_entries(&self) -> Vec<Entry> {
        self.entries_for_prefix(&crate::cryptofmt::RAW_PREFIX)
    }

    /// Return all primitives in the set that have the given prefix.
    pub fn entries_for_prefix(&self, prefix: &[u8]) -> Vec<Entry> {
        match self.entries.get(prefix) {
            Some(v) => v.clone(),
            None => Vec::new(),
        }
    }

    /// Create a new entry in the primitive set and returns a copy of the added entry.
    pub fn add(
        &mut self,
        p: crate::Primitive,
        key: &tink_proto::keyset::Key,
    ) -> Result<Entry, TinkError> {
        if key.status != tink_proto::KeyStatusType::Enabled as i32 {
            return Err("The key must be ENABLED".into());
        }
        let prefix =
            crate::cryptofmt::output_prefix(key).map_err(|e| wrap_err("primitiveset", e))?;
        let entry = Entry::new(
            key.key_id,
            p,
            &prefix,
            tink_proto::OutputPrefixType::from_i32(key.output_prefix_type)
                .ok_or_else(|| TinkError::new("invalid key prefix type"))?,
            tink_proto::KeyStatusType::from_i32(key.status)
                .ok_or_else(|| TinkError::new("invalid key status"))?,
        );
        let retval = entry.clone();
        match self.entries.entry(prefix) {
            btree_map::Entry::Occupied(mut oe) => oe.get_mut().push(entry),
            btree_map::Entry::Vacant(ve) => {
                ve.insert(vec![entry]);
            }
        };
        Ok(retval)
    }
}

/// `TypedEntry` represents a single entry in a keyset for primitives of a known type. In addition
/// to the actual primitive, it holds the identifier and status of the primitive.
pub struct TypedEntry<P: From<crate::Primitive>> {
    pub key_id: crate::KeyId,
    pub primitive: P,
    pub prefix: Vec<u8>,
    pub prefix_type: tink_proto::OutputPrefixType,
    pub status: tink_proto::KeyStatusType,
}

impl<P: From<crate::Primitive>> From<Entry> for TypedEntry<P> {
    fn from(entry: Entry) -> Self {
        Self {
            key_id: entry.key_id,
            primitive: entry.primitive.into(),
            prefix: entry.prefix,
            prefix_type: entry.prefix_type,
            status: entry.status,
        }
    }
}

/// `TypedPrimitiveSet` is equivalent to [`PrimitiveSet`] but holds primitives
/// of a specific known type `P`.
pub struct TypedPrimitiveSet<P: From<crate::Primitive>> {
    // Copy of the primary entry in `entries`.
    pub primary: Option<TypedEntry<P>>,

    // The primitives are stored in a map of (ciphertext prefix, list of
    // primitives sharing the prefix). This allows quickly retrieving the
    // primitives sharing some particular prefix.
    pub entries: BTreeMap<Vec<u8>, Vec<TypedEntry<P>>>,
}

impl<P: From<crate::Primitive>> TypedPrimitiveSet<P> {
    /// Return all primitives in the set that have RAW prefix.
    pub fn raw_entries(&self) -> Option<&Vec<TypedEntry<P>>> {
        self.entries_for_prefix(&crate::cryptofmt::RAW_PREFIX)
    }

    /// Return all primitives in the set that have the given prefix.
    pub fn entries_for_prefix(&self, prefix: &[u8]) -> Option<&Vec<TypedEntry<P>>> {
        self.entries.get(prefix)
    }
}

/// A `TypedPrimitiveSet` is [`Clone`]able if its constituent [`TypedEntry`] objects
/// are [`Clone`]able.
impl<T> Clone for TypedPrimitiveSet<T>
where
    TypedEntry<T>: Clone,
    T: From<crate::Primitive>,
{
    fn clone(&self) -> Self {
        Self {
            primary: self.primary.as_ref().cloned(),
            entries: self.entries.clone(),
        }
    }
}

/// Convert an untyped [`PrimitiveSet`] into a [`TypedPrimitiveSet`]. This will
/// panic if any of the primitives are not of the correct type.
impl<P: From<crate::Primitive>> From<PrimitiveSet> for TypedPrimitiveSet<P> {
    fn from(ps: PrimitiveSet) -> Self {
        Self {
            primary: ps.primary.map(|e| e.into()),
            entries: ps
                .entries
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(TypedEntry::<P>::from).collect()))
                .collect(),
        }
    }
}

// When used for a primitive, instances of `TypedPrimitiveSet` need to support `Clone`.
// This is possible for each primitive type individually using the `box_clone()` method,
// but needs a specialized implementation of `Clone` for each primitive.

impl Clone for TypedEntry<Box<dyn crate::Aead>> {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            primitive: self.primitive.box_clone(),
            prefix: self.prefix.clone(),
            prefix_type: self.prefix_type,
            status: self.status,
        }
    }
}
impl Clone for TypedEntry<Box<dyn crate::DeterministicAead>> {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            primitive: self.primitive.box_clone(),
            prefix: self.prefix.clone(),
            prefix_type: self.prefix_type,
            status: self.status,
        }
    }
}
impl Clone for TypedEntry<Box<dyn crate::Mac>> {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            primitive: self.primitive.box_clone(),
            prefix: self.prefix.clone(),
            prefix_type: self.prefix_type,
            status: self.status,
        }
    }
}
impl Clone for TypedEntry<Box<dyn crate::Signer>> {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            primitive: self.primitive.box_clone(),
            prefix: self.prefix.clone(),
            prefix_type: self.prefix_type,
            status: self.status,
        }
    }
}
#[cfg(feature = "std")]
impl Clone for TypedEntry<Box<dyn crate::StreamingAead>> {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            primitive: self.primitive.box_clone(),
            prefix: self.prefix.clone(),
            prefix_type: self.prefix_type,
            status: self.status,
        }
    }
}
impl Clone for TypedEntry<Box<dyn crate::Verifier>> {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            primitive: self.primitive.box_clone(),
            prefix: self.prefix.clone(),
            prefix_type: self.prefix_type,
            status: self.status,
        }
    }
}
