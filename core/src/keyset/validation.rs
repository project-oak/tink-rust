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

//! Keyset validation functions.

use crate::TinkError;

/// Check whether the given version is valid. The version is valid
/// only if it is the range [0..max_expected].
pub fn validate_key_version(version: u32, max_expected: u32) -> Result<(), TinkError> {
    if version > max_expected {
        Err(format!(
            "key has version {}; only keys with version in range [0..{}] are supported",
            version, max_expected
        )
        .into())
    } else {
        Ok(())
    }
}

/// Validate the given key set.
pub fn validate(keyset: &tink_proto::Keyset) -> Result<(), TinkError> {
    if keyset.key.is_empty() {
        return Err("empty keyset".into());
    }
    let primary_key_id = keyset.primary_key_id;
    let mut has_primary_key = false;
    let mut contains_only_pub = true;
    let mut num_enabled_keys = 0;
    for key in &keyset.key {
        validate_key(&key)?;
        if key.status != tink_proto::KeyStatusType::Enabled as i32 {
            continue;
        }
        if key.key_id == primary_key_id {
            if has_primary_key {
                return Err("keyset contains multiple primary keys".into());
            }
            has_primary_key = true;
        }
        if let Some(key_data) = &key.key_data {
            if key_data.key_material_type
                != tink_proto::key_data::KeyMaterialType::AsymmetricPublic as i32
            {
                contains_only_pub = false;
            }
        }
        num_enabled_keys += 1;
    }
    if num_enabled_keys == 0 {
        Err("keyset must contain at least one ENABLED key".into())
    } else if !has_primary_key && !contains_only_pub {
        Err("keyset does not contain a valid primary key".into())
    } else {
        Ok(())
    }
}

/// Validate the given key.
pub fn validate_key(key: &tink_proto::keyset::Key) -> Result<(), TinkError> {
    if key.key_id == 0 {
        Err(format!("key has zero key id: {}", key.key_id).into())
    } else if key.key_data.is_none() {
        Err(format!("key {} has no key data", key.key_id).into())
    } else if key.output_prefix_type != tink_proto::OutputPrefixType::Tink as i32
        && key.output_prefix_type != tink_proto::OutputPrefixType::Legacy as i32
        && key.output_prefix_type != tink_proto::OutputPrefixType::Raw as i32
        && key.output_prefix_type != tink_proto::OutputPrefixType::Crunchy as i32
    {
        Err(format!("key {} has unknown prefix", key.key_id).into())
    } else if key.status != tink_proto::KeyStatusType::Enabled as i32
        && key.status != tink_proto::KeyStatusType::Disabled as i32
        && key.status != tink_proto::KeyStatusType::Destroyed as i32
    {
        Err(format!("key {} has unknown status", key.key_id).into())
    } else {
        Ok(())
    }
}
