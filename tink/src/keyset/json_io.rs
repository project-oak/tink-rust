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

use crate::TinkError;

// TODO: supporting JSON requires that the prost-generated code include
// [derive(Serialize,Deserialize)] for each message, which in turn means that build.rs would need to
// produce differently generated code depending on a `json` feature (and the generated code couldn't
// be checked in).

/// `JSONReader` deserializes a keyset from JSON format.
pub struct JSONReader {
    r: Box<dyn std::io::Read>,
}

impl JSONReader {
    /// Return a new [`JSONReader`] that will read from `r`.
    pub fn new(r: Box<dyn std::io::Read>) -> Self {
        JSONReader { r }
    }
}

impl super::Reader for JSONReader {
    /// Return a (cleartext) [`Keyset`](crate::proto::Keyset) object from the underlying
    /// [`std::io::Read`].
    fn read(&mut self) -> Result<crate::proto::Keyset, TinkError> {
        read_json::<crate::proto::Keyset>(&mut self.r)
    }

    /// Return an [`EncryptedKeyset`](crate::proto::EncryptedKeyset) object from the underlying
    /// [`std::io::Read`].
    fn read_encrypted(&mut self) -> Result<crate::proto::EncryptedKeyset, TinkError> {
        read_json::<crate::proto::EncryptedKeyset>(&mut self.r)
    }
}

fn read_json<T>(r: &mut Box<dyn std::io::Read>) -> Result<T, TinkError>
where
    T: prost::Message + std::default::Default,
{
    match serde_json::from_reader(r) {
        Ok(msg) => Ok(msg),
        Err(e) => Err(e),
    }
}

/// `JSONWriter` serializes a keyset into binary proto format.
pub struct JSONWriter {
    w: Box<dyn std::io::Write>,
}

impl JSONWriter {
    /// Return a new [`JSONWriter`] that will write to `w`.
    pub fn new(w: Box<dyn std::io::Write>) -> Self {
        JSONWriter { w }
    }
}

impl super::Writer for JSONWriter {
    /// Write the keyset to the underlying [`std::io::Write`].
    fn write(&mut self, keyset: &crate::proto::Keyset) -> Result<(), TinkError> {
        write_json(&mut self.w, keyset)
    }

    /// Write the encrypted keyset to the underlying [`std::io::Write`].
    fn write_encrypted(&mut self, keyset: &crate::proto::EncryptedKeyset) -> Result<(), TinkError> {
        write_json(&mut self.w, keyset)
    }
}

fn write_json<T>(w: &mut Box<dyn std::io::Write>, msg: &T) -> Result<(), TinkError>
where
    T: prost::Message,
{
    let data = serde_json::to_vec(msg)?;
    match w.write(&data) {
        Ok(_size) => Ok(()),
        Err(e) => Err(e),
    }
}
