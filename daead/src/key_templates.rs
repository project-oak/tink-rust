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

//! This module contains pre-generated [`KeyTemplate`] instances for deterministic AEAD.

use tink::proto::KeyTemplate;

/// Return a [`KeyTemplate`](tink::proto::KeyTemplate) that generates a AES-SIV key.
pub fn aes_siv_key_template() -> KeyTemplate {
    KeyTemplate {
        // Don't set value because KeyFormat is not required.
        value: Vec::new(),
        type_url: crate::AES_SIV_TYPE_URL.to_string(),
        output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
    }
}
