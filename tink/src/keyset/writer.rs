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

//! Trait definition for writing keysets.

/// `Writer` knows how to write a [`Keyset`](crate::proto::Keyset) or an
/// [`EncryptedKeyset`](crate::proto::EncryptedKeyset) to some source.
pub trait Writer {
    // Write keyset to some storage system.
    fn write(&mut self, keyset: &crate::proto::Keyset) -> Result<(), crate::TinkError>;

    // Write `EncryptedKeyset` to some storage system.
    fn write_encrypted(
        &mut self,
        keyset: &crate::proto::EncryptedKeyset,
    ) -> Result<(), crate::TinkError>;
}
