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

//! In-memory I/O for keysets (typically for testing).

use crate::TinkError;

/// `MemReaderWriter` implements [`keyset::Reader`](super::Reader) and
/// [`keyset.Writer`](super::Writer) with in-memory storage.
#[derive(Default)]
pub struct MemReaderWriter {
    pub keyset: Option<tink_proto::Keyset>,
    pub encrypted_keyset: Option<tink_proto::EncryptedKeyset>,
}

impl super::Reader for MemReaderWriter {
    /// Return `Keyset` from memory.
    fn read(&mut self) -> Result<tink_proto::Keyset, TinkError> {
        match &self.keyset {
            Some(keyset) => Ok(keyset.clone()),
            None => Err("no keyset available".into()),
        }
    }

    /// Return `EncryptedKeyset` from memory.
    fn read_encrypted(&mut self) -> Result<tink_proto::EncryptedKeyset, TinkError> {
        match &self.encrypted_keyset {
            Some(keyset) => Ok(keyset.clone()),
            None => Err("no keyset available".into()),
        }
    }
}

impl super::Writer for MemReaderWriter {
    /// Write keyset to memory.
    fn write(&mut self, keyset: &tink_proto::Keyset) -> Result<(), TinkError> {
        self.keyset = Some(keyset.clone());
        Ok(())
    }

    /// Write encrypted keyset to memory.
    fn write_encrypted(&mut self, keyset: &tink_proto::EncryptedKeyset) -> Result<(), TinkError> {
        self.encrypted_keyset = Some(keyset.clone());
        Ok(())
    }
}
