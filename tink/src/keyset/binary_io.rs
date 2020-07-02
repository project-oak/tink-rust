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

//! Binary I/O for keysets.

use crate::{utils::wrap_err, TinkError};
use std::io::{Read, Write};

/// `BinaryReader` deserializes a keyset from binary proto format.
pub struct BinaryReader<T: Read> {
    r: T,
}

impl<T: Read> BinaryReader<T> {
    /// Return a new [`BinaryReader`] that will read from `r`.
    pub fn new(r: T) -> Self {
        BinaryReader { r }
    }
}

impl<T: Read> super::Reader for BinaryReader<T> {
    /// Return a (cleartext) [`Keyset`](crate::proto::Keyset) object from the underlying
    /// [`std::io::Read`].
    fn read(&mut self) -> Result<crate::proto::Keyset, TinkError> {
        read::<crate::proto::Keyset>(&mut self.r)
    }

    /// Return an [`EncryptedKeyset`](crate::proto::EncryptedKeyset) object from the underlying
    /// [`std::io::Read`].
    fn read_encrypted(&mut self) -> Result<crate::proto::EncryptedKeyset, TinkError> {
        read::<crate::proto::EncryptedKeyset>(&mut self.r)
    }
}

fn read<T>(r: &mut dyn Read) -> Result<T, TinkError>
where
    T: prost::Message + std::default::Default,
{
    let mut data = vec![];
    r.read_to_end(&mut data)
        .map_err(|e| wrap_err("read failed", e))?;
    match T::decode(data.as_ref()) {
        Ok(msg) => Ok(msg),
        Err(e) => Err(wrap_err("decode failed", e)),
    }
}

/// `BinaryWriter` serializes a keyset into binary proto format.
pub struct BinaryWriter<T: Write> {
    w: T,
}

impl<T: Write> BinaryWriter<T> {
    /// Return a new [`BinaryWriter`] that will write to `w`.
    pub fn new(w: T) -> Self {
        BinaryWriter { w }
    }
}

impl<T: Write> super::Writer for BinaryWriter<T> {
    /// Write the keyset to the underlying [`std::io::Write`].
    fn write(&mut self, keyset: &crate::proto::Keyset) -> Result<(), TinkError> {
        write(&mut self.w, keyset)
    }

    /// Write the encrypted keyset to the underlying [`std::io::Write`].
    fn write_encrypted(&mut self, keyset: &crate::proto::EncryptedKeyset) -> Result<(), TinkError> {
        write(&mut self.w, keyset)
    }
}

fn write<T>(w: &mut dyn Write, msg: &T) -> Result<(), TinkError>
where
    T: prost::Message,
{
    let mut data = vec![];
    match msg.encode(&mut data) {
        Ok(()) => Ok(()),
        Err(e) => Err(wrap_err("encode failed", e)),
    }?;
    match w.write(&data) {
        Ok(_size) => Ok(()),
        Err(e) => Err(wrap_err("write failed", e)),
    }
}
