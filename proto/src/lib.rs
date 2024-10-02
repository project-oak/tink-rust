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
//!
//! Almost all of the code in this crate is auto-generated (using [prost](https://docs.rs/prost)) from the protocol
//! buffer message definitions in the `proto/` subdirectory.  These `.proto` files are copies from
//! the upstream [Tink project](https://github.com/google/tink/tree/master/proto).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(broken_intra_doc_links)]
#![allow(clippy::derive_partial_eq_without_eq)]

/// Re-export to ensure that users of this crate can access the same version.
pub use prost;

#[cfg(not(feature = "json"))]
include!("codegen/google.crypto.tink.rs");
#[cfg(feature = "json")]
include!("codegen/serde/google.crypto.tink.rs");

// Manual keyset serialization implementations that map enums onto strings rather than
// the `i32` values used by [prost](https://docs.rs/prost).
#[cfg(feature = "json")]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
pub mod json {
    pub mod key_status_type {
        //! Manual JSON serialization for [`KeyStatusType`](crate::KeyStatusType) enums.
        use serde::Deserialize;
        use std::convert::TryFrom;
        pub fn serialize<S: serde::Serializer>(
            val: &i32,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(match crate::KeyStatusType::try_from(*val) {
                Ok(crate::KeyStatusType::Enabled) => "ENABLED",
                Ok(crate::KeyStatusType::Disabled) => "DISABLED",
                Ok(crate::KeyStatusType::Destroyed) => "DESTROYED",
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
        use std::convert::TryFrom;
        pub fn serialize<S: serde::Serializer>(
            val: &i32,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(match crate::OutputPrefixType::try_from(*val) {
                Ok(crate::OutputPrefixType::Tink) => "TINK",
                Ok(crate::OutputPrefixType::Legacy) => "LEGACY",
                Ok(crate::OutputPrefixType::Raw) => "RAW",
                Ok(crate::OutputPrefixType::Crunchy) => "CRUNCHY",
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
        use std::convert::TryFrom;
        pub fn serialize<S: serde::Serializer>(
            val: &i32,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(match crate::key_data::KeyMaterialType::try_from(*val) {
                Ok(crate::key_data::KeyMaterialType::Symmetric) => "SYMMETRIC",
                Ok(crate::key_data::KeyMaterialType::AsymmetricPrivate) => "ASYMMETRIC_PRIVATE",
                Ok(crate::key_data::KeyMaterialType::AsymmetricPublic) => "ASYMMETRIC_PUBLIC",
                Ok(crate::key_data::KeyMaterialType::Remote) => "REMOTE",
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
        use base64::Engine;
        use serde::Deserialize;
        pub fn serialize<S: serde::Serializer>(
            val: &[u8],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(val))
        }
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<u8>, D::Error> {
            let s = String::deserialize(deserializer)?;
            base64::engine::general_purpose::STANDARD
                .decode(&s)
                .map_err(|_e| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(&s),
                        &"base64 data expected",
                    )
                })
        }
    }
}
