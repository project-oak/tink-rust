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

//! Trait definition for reading keysets.

/// `Reader` knows how to read a [`Keyset`](crate::proto::Keyset) or an
/// [`EncryptedKeyset`](crate::proto::EncryptedKeyset) from some source. In order to turn a `Reader`
/// into a [`keyset::Handle`](crate::keyset::Handle) for use, callers must use
/// [`insecure::new_handle`](super::insecure::new_handle) or
/// [`Handle::read`](super::Handle::read) (with encryption).
pub trait Reader {
    /// Return a (cleartext) `Keyset` object from the underlying source.
    fn read(&mut self) -> Result<crate::proto::Keyset, crate::TinkError>;

    /// Return an `EncryptedKeyset` object from the underlying source.
    fn read_encrypted(&mut self) -> Result<crate::proto::EncryptedKeyset, crate::TinkError>;
}
