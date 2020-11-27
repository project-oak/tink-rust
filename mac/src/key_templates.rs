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

//! This module contains pre-generated [`KeyTemplate`] instances for MAC.

use prost::Message;
use tink::proto::KeyTemplate;

/// Return a [`KeyTemplate`] that generates a HMAC key with the following parameters:
///  - Key size: 32 bytes
///  - Tag size: 16 bytes
///  - Hash function: SHA256
pub fn hmac_sha256_tag128_key_template() -> KeyTemplate {
    create_hmac_key_template(32, 16, tink::proto::HashType::Sha256)
}

/// Return a [`KeyTemplate`] that generates a HMAC key with the following parameters:
///  - Key size: 32 bytes
///  - Tag size: 32 bytes
///  - Hash function: SHA256
pub fn hmac_sha256_tag256_key_template() -> KeyTemplate {
    create_hmac_key_template(32, 32, tink::proto::HashType::Sha256)
}

/// Return a [`KeyTemplate`] that generates a HMAC key with the following parameters:
///  - Key size: 64 bytes
///  - Tag size: 32 bytes
///  - Hash function: SHA512
pub fn hmac_sha512_tag256_key_template() -> KeyTemplate {
    create_hmac_key_template(64, 32, tink::proto::HashType::Sha512)
}

/// Return a [`KeyTemplate`] that generates a HMAC key with the following parameters:
///  - Key size: 64 bytes
///  - Tag size: 64 bytes
///  - Hash function: SHA512
pub fn hmac_sha512_tag512_key_template() -> KeyTemplate {
    create_hmac_key_template(64, 64, tink::proto::HashType::Sha512)
}

/// Return a [`KeyTemplate`] that generates a AES-CMAC key with the following parameters:
///  - Key size: 32 bytes
///  - Tag size: 16 bytes
pub fn aes_cmac_tag128_key_template() -> KeyTemplate {
    create_cmac_key_template(32, 16)
}

/// Create a new [`KeyTemplate`] for HMAC using the given parameters.
fn create_hmac_key_template(
    key_size: u32,
    tag_size: u32,
    hash_type: tink::proto::HashType,
) -> KeyTemplate {
    let params = tink::proto::HmacParams {
        hash: hash_type as i32,
        tag_size,
    };
    let format = tink::proto::HmacKeyFormat {
        version: crate::HMAC_KEY_VERSION,
        params: Some(params),
        key_size,
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap(); // safe: proto-encode
    KeyTemplate {
        type_url: crate::HMAC_TYPE_URL.to_string(),
        value: serialized_format,
        output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
    }
}

/// Create a new [`KeyTemplate`] for CMAC using the given parameters.
fn create_cmac_key_template(key_size: u32, tag_size: u32) -> KeyTemplate {
    let params = tink::proto::AesCmacParams { tag_size };
    let format = tink::proto::AesCmacKeyFormat {
        params: Some(params),
        key_size,
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap(); // safe: proto-encode
    KeyTemplate {
        type_url: crate::CMAC_TYPE_URL.to_string(),
        value: serialized_format,
        output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
    }
}
