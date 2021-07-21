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

//! JSON I/O for keysets (requires activation of the `json` feature).

use crate::{utils::wrap_err, TinkError};
use serde::Deserialize;
use std::io::{Read, Write};

/// `JsonReader` deserializes a keyset from JSON format.
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
pub struct JsonReader<T: Read> {
    r: T,
}

impl<T: Read> JsonReader<T> {
    /// Return a new [`JsonReader`] that will read from `r`.
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    pub fn new(r: T) -> Self {
        JsonReader { r }
    }
}

impl<T: Read> super::Reader for JsonReader<T> {
    /// Return a (cleartext) [`Keyset`](tink_proto::Keyset) object from the underlying
    /// [`std::io::Read`].
    fn read(&mut self) -> Result<tink_proto::Keyset, TinkError> {
        let mut de = serde_json::Deserializer::from_reader(&mut self.r);
        tink_proto::Keyset::deserialize(&mut de).map_err(|e| wrap_err("failed to parse", e))
    }

    /// Return an [`EncryptedKeyset`](tink_proto::EncryptedKeyset) object from the underlying
    /// [`std::io::Read`].
    fn read_encrypted(&mut self) -> Result<tink_proto::EncryptedKeyset, TinkError> {
        let mut de = serde_json::Deserializer::from_reader(&mut self.r);
        tink_proto::EncryptedKeyset::deserialize(&mut de)
            .map_err(|e| wrap_err("failed to parse", e))
    }
}

/// `JsonWriter` serializes a keyset into JSON format.
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
pub struct JsonWriter<T: Write> {
    w: T,
}

impl<T: Write> JsonWriter<T> {
    /// Return a new [`JsonWriter`] that will write to `w`.
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    pub fn new(w: T) -> Self {
        JsonWriter { w }
    }
}

impl<T: Write> super::Writer for JsonWriter<T> {
    /// Write the keyset to the underlying [`std::io::Write`].
    fn write(&mut self, keyset: &tink_proto::Keyset) -> Result<(), TinkError> {
        serde_json::to_writer_pretty(&mut self.w, keyset)
            .map_err(|e| wrap_err("failed to encode", e))
    }

    /// Write the encrypted keyset to the underlying [`std::io::Write`].
    fn write_encrypted(&mut self, keyset: &tink_proto::EncryptedKeyset) -> Result<(), TinkError> {
        serde_json::to_writer_pretty(&mut self.w, keyset)
            .map_err(|e| wrap_err("failed to encode", e))
    }
}
