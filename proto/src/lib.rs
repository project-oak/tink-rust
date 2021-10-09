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

//! Protocol buffer message definitions for Tink.

#![deny(broken_intra_doc_links)]

/// Re-export to ensure that users of this crate can access the same version.
pub use prost;

#[cfg(not(feature = "json"))]
include!("codegen/google.crypto.tink.rs");
#[cfg(feature = "json")]
include!("codegen/serde/google.crypto.tink.rs");

#[cfg(feature = "json")]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
pub mod json {
    //! Manual keyset serialization implementations that map enums onto strings rather than
    //! the `i32` values used by prost.
    pub mod key_status_type {
        //! Manual JSON serialization for [`KeyStatusType`](crate::KeyStatusType) enums.
        use serde::Deserialize;
        pub fn serialize<S: serde::Serializer>(
            val: &i32,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(match crate::KeyStatusType::from_i32(*val) {
                Some(crate::KeyStatusType::Enabled) => "ENABLED",
                Some(crate::KeyStatusType::Disabled) => "DISABLED",
                Some(crate::KeyStatusType::Destroyed) => "DESTROYED",
                _ => "UNKNOWN",
            })
        }
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<i32, D::Error> {
            let s = String::deserialize(deserializer)?;
            Ok(match s.as_ref() {
                "ENABLED" => crate::KeyStatusType::Enabled as i32,
                "DISABLED" => crate::KeyStatusType::Disabled as i32,
                "DESTROYED" => crate::KeyStatusType::Destroyed as i32,
                _ => crate::KeyStatusType::UnknownStatus as i32,
            })
        }
    }
    pub mod output_prefix_type {
        //! Manual JSON serialization for [`OutputPrefixType`](crate::OutputPrefixType) enums.
        use serde::Deserialize;
        pub fn serialize<S: serde::Serializer>(
            val: &i32,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(match crate::OutputPrefixType::from_i32(*val) {
                Some(crate::OutputPrefixType::Tink) => "TINK",
                Some(crate::OutputPrefixType::Legacy) => "LEGACY",
                Some(crate::OutputPrefixType::Raw) => "RAW",
                Some(crate::OutputPrefixType::Crunchy) => "CRUNCHY",
                _ => "UNKNOWN",
            })
        }
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<i32, D::Error> {
            let s = String::deserialize(deserializer)?;
            Ok(match s.as_ref() {
                "TINK" => crate::OutputPrefixType::Tink as i32,
                "LEGACY" => crate::OutputPrefixType::Legacy as i32,
                "RAW" => crate::OutputPrefixType::Raw as i32,
                "CRUNCHY" => crate::OutputPrefixType::Crunchy as i32,
                _ => crate::OutputPrefixType::UnknownPrefix as i32,
            })
        }
    }
    pub mod key_material_type {
        //! Manual JSON serialization for [`KeyMaterialType`](crate::key_data::KeyMaterialType)
        //! enums.
        use serde::Deserialize;
        pub fn serialize<S: serde::Serializer>(
            val: &i32,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(match crate::key_data::KeyMaterialType::from_i32(*val) {
                Some(crate::key_data::KeyMaterialType::Symmetric) => "SYMMETRIC",
                Some(crate::key_data::KeyMaterialType::AsymmetricPrivate) => "ASYMMETRIC_PRIVATE",
                Some(crate::key_data::KeyMaterialType::AsymmetricPublic) => "ASYMMETRIC_PUBLIC",
                Some(crate::key_data::KeyMaterialType::Remote) => "REMOTE",
                _ => "UNKNOWN",
            })
        }
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<i32, D::Error> {
            let s = String::deserialize(deserializer)?;
            Ok(match s.as_ref() {
                "SYMMETRIC" => crate::key_data::KeyMaterialType::Symmetric as i32,
                "ASYMMETRIC_PRIVATE" => crate::key_data::KeyMaterialType::AsymmetricPrivate as i32,
                "ASYMMETRIC_PUBLIC" => crate::key_data::KeyMaterialType::AsymmetricPublic as i32,
                "REMOTE" => crate::key_data::KeyMaterialType::Remote as i32,
                _ => crate::key_data::KeyMaterialType::UnknownKeymaterial as i32,
            })
        }
    }
    pub mod b64 {
        //! Manual serialization implementations for base64-encoded binary data.
        use serde::Deserialize;
        pub fn serialize<S: serde::Serializer>(
            val: &[u8],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&base64::encode(val))
        }
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<u8>, D::Error> {
            let s = String::deserialize(deserializer)?;
            base64::decode(&s).map_err(|_e| {
                serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(&s),
                    &"base64 data expected",
                )
            })
        }
    }
}
