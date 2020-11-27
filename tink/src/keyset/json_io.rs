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

//! JSON I/O for keysets.

use crate::{utils::wrap_err, TinkError};
use serde::Deserialize;
use std::io::{Read, Write};

/// `JsonReader` deserializes a keyset from JSON format.
pub struct JsonReader<T: Read> {
    r: T,
}

impl<T: Read> JsonReader<T> {
    /// Return a new [`JsonReader`] that will read from `r`.
    pub fn new(r: T) -> Self {
        JsonReader { r }
    }
}

impl<T: Read> super::Reader for JsonReader<T> {
    /// Return a (cleartext) [`Keyset`](crate::proto::Keyset) object from the underlying
    /// [`std::io::Read`].
    fn read(&mut self) -> Result<crate::proto::Keyset, TinkError> {
        let mut de = serde_json::Deserializer::from_reader(&mut self.r);
        crate::proto::Keyset::deserialize(&mut de).map_err(|e| wrap_err("failed to parse", e))
    }

    /// Return an [`EncryptedKeyset`](crate::proto::EncryptedKeyset) object from the underlying
    /// [`std::io::Read`].
    fn read_encrypted(&mut self) -> Result<crate::proto::EncryptedKeyset, TinkError> {
        let mut de = serde_json::Deserializer::from_reader(&mut self.r);
        crate::proto::EncryptedKeyset::deserialize(&mut de)
            .map_err(|e| wrap_err("failed to parse", e))
    }
}

/// `JsonWriter` serializes a keyset into binary proto format.
pub struct JsonWriter<T: Write> {
    w: T,
}

impl<T: Write> JsonWriter<T> {
    /// Return a new [`JsonWriter`] that will write to `w`.
    pub fn new(w: T) -> Self {
        JsonWriter { w }
    }
}

impl<T: Write> super::Writer for JsonWriter<T> {
    /// Write the keyset to the underlying [`std::io::Write`].
    fn write(&mut self, keyset: &crate::proto::Keyset) -> Result<(), TinkError> {
        serde_json::to_writer_pretty(&mut self.w, keyset)
            .map_err(|e| wrap_err("failed to encode", e))
    }

    /// Write the encrypted keyset to the underlying [`std::io::Write`].
    fn write_encrypted(&mut self, keyset: &crate::proto::EncryptedKeyset) -> Result<(), TinkError> {
        serde_json::to_writer_pretty(&mut self.w, keyset)
            .map_err(|e| wrap_err("failed to encode", e))
    }
}

// Manual serialization implementations that map enums onto strings rather than
// the `i32` values used by prost.
pub mod key_status_type {
    //! Manual JSON serialization for [`KeyStatusType`](crate::proto::KeyStatusType) enums.
    use serde::Deserialize;
    pub fn serialize<S: serde::Serializer>(val: &i32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match crate::proto::KeyStatusType::from_i32(*val) {
            Some(crate::proto::KeyStatusType::Enabled) => "ENABLED",
            Some(crate::proto::KeyStatusType::Disabled) => "DISABLED",
            Some(crate::proto::KeyStatusType::Destroyed) => "DESTROYED",
            _ => "UNKNOWN",
        })
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_ref() {
            "ENABLED" => crate::proto::KeyStatusType::Enabled as i32,
            "DISABLED" => crate::proto::KeyStatusType::Disabled as i32,
            "DESTROYED" => crate::proto::KeyStatusType::Destroyed as i32,
            _ => crate::proto::KeyStatusType::UnknownStatus as i32,
        })
    }
}
pub mod output_prefix_type {
    //! Manual JSON serialization for [`OutputPrefixType`](crate::proto::OutputPrefixType) enums.
    use serde::Deserialize;
    pub fn serialize<S: serde::Serializer>(val: &i32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match crate::proto::OutputPrefixType::from_i32(*val) {
            Some(crate::proto::OutputPrefixType::Tink) => "TINK",
            Some(crate::proto::OutputPrefixType::Legacy) => "LEGACY",
            Some(crate::proto::OutputPrefixType::Raw) => "RAW",
            Some(crate::proto::OutputPrefixType::Crunchy) => "CRUNCHY",
            _ => "UNKNOWN",
        })
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_ref() {
            "TINK" => crate::proto::OutputPrefixType::Tink as i32,
            "LEGACY" => crate::proto::OutputPrefixType::Legacy as i32,
            "RAW" => crate::proto::OutputPrefixType::Raw as i32,
            "CRUNCHY" => crate::proto::OutputPrefixType::Crunchy as i32,
            _ => crate::proto::OutputPrefixType::UnknownPrefix as i32,
        })
    }
}
pub mod key_material_type {
    //! Manual JSON serialization for [`KeyMaterialType`](crate::proto::key_data::KeyMaterialType)
    //! enums.
    use serde::Deserialize;
    pub fn serialize<S: serde::Serializer>(val: &i32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(
            match crate::proto::key_data::KeyMaterialType::from_i32(*val) {
                Some(crate::proto::key_data::KeyMaterialType::Symmetric) => "SYMMETRIC",
                Some(crate::proto::key_data::KeyMaterialType::AsymmetricPrivate) => {
                    "ASYMMETRIC_PRIVATE"
                }
                Some(crate::proto::key_data::KeyMaterialType::AsymmetricPublic) => {
                    "ASYMMETRIC_PUBLIC"
                }
                Some(crate::proto::key_data::KeyMaterialType::Remote) => "REMOTE",
                _ => "UNKNOWN",
            },
        )
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_ref() {
            "SYMMETRIC" => crate::proto::key_data::KeyMaterialType::Symmetric as i32,
            "ASYMMETRIC_PRIVATE" => {
                crate::proto::key_data::KeyMaterialType::AsymmetricPrivate as i32
            }
            "ASYMMETRIC_PUBLIC" => crate::proto::key_data::KeyMaterialType::AsymmetricPublic as i32,
            "REMOTE" => crate::proto::key_data::KeyMaterialType::Remote as i32,
            _ => crate::proto::key_data::KeyMaterialType::UnknownKeymaterial as i32,
        })
    }
}
pub mod b64 {
    //! Manual serialization implementations for base64-encoded binary data.
    use serde::Deserialize;
    pub fn serialize<S: serde::Serializer>(val: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::encode(val))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        base64::decode(&s).map_err(|_e| {
            serde::de::Error::invalid_value(serde::de::Unexpected::Str(&s), &"base64 data expected")
        })
    }
}
